use crate::config::{Ownership, ResolvedLdapConfig};
use crate::connection::connect;
use crate::dn::{same_dn, split_rdn_parent};
use crate::live::{live_tree, LiveAttrs};
use crate::operations::{
  entry_add, entry_delete, entry_modify, entry_modifydn, list_entries,
  naming_contexts, OperationError,
};
use crate::runbook::{
  to_runbook_steps, LdapChange, LdapOperation, RunbookError,
};
use crate::search_base::SearchBase;
use async_trait::async_trait;
use futures::future::try_join_all;
use ldap3::{Ldap, Mod};
use nix_hapi_lib::meta::NixHapiMeta;
use nix_hapi_lib::plan::{ApplyReport, ProviderPlanWave, RunbookStep};
use nix_hapi_lib::provider::{Filter, Provider, ProviderError, ResolvedConfig};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use tracing::info;

pub struct LdapProvider;

#[async_trait]
impl Provider for LdapProvider {
  fn provider_type(&self) -> &str {
    "ldap"
  }

  fn sensitive_config_fields(&self) -> &[&str] {
    &["bindPassword"]
  }

  async fn list_live(
    &self,
    config: &ResolvedConfig,
    _filters: &[Filter],
  ) -> Result<Value, ProviderError> {
    let ldap_config = ResolvedLdapConfig::from_resolved_config(config)?;
    let mut ldap = connect(&ldap_config).await?;
    let bases = owned_bases(&mut ldap, &ldap_config).await.map_err(op_err)?;
    query_live(&ldap, &bases).await.map_err(op_err)
  }

  async fn build_runbook(
    &self,
    wave: &ProviderPlanWave,
    _desired: &Value,
    _live: &Value,
    _meta: &NixHapiMeta,
    config: &ResolvedConfig,
  ) -> Result<Vec<RunbookStep>, ProviderError> {
    let ldap_config = ResolvedLdapConfig::from_resolved_config(config)?;
    let bases = bases_for_planning(&ldap_config).await?;
    to_runbook_steps(&wave.changes, &ldap_config, &bases).map_err(runbook_err)
  }

  async fn apply(
    &self,
    wave: &ProviderPlanWave,
    config: &ResolvedConfig,
  ) -> Result<ApplyReport, ProviderError> {
    let ldap_config = ResolvedLdapConfig::from_resolved_config(config)?;
    let mut ldap = connect(&ldap_config).await?;
    let bases = owned_bases(&mut ldap, &ldap_config).await.map_err(op_err)?;
    let mut report = ApplyReport::default();

    let steps = to_runbook_steps(&wave.changes, &ldap_config, &bases)
      .map_err(runbook_err)?;
    for step in steps {
      let op: LdapOperation = serde_json::from_value(step.operation.clone())
        .map_err(|e| {
          ProviderError::OperationFailed(format!(
            "Failed to deserialise operation for {:?}: {}",
            step.description, e
          ))
        })?;
      execute_op(&mut ldap, op, &mut report).await?;
    }
    Ok(report)
  }
}

async fn execute_op(
  ldap: &mut Ldap,
  op: LdapOperation,
  report: &mut ApplyReport,
) -> Result<(), ProviderError> {
  match op {
    LdapOperation::Add { dn, attrs } => {
      info!(dn = %dn, "Adding entry");
      let owned: Vec<(String, HashSet<String>)> = attrs
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect();
      let borrowed: Vec<(&str, HashSet<&str>)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.iter().map(String::as_str).collect()))
        .collect();
      entry_add(ldap, &dn, borrowed).await.map_err(op_err)?;
      report.created.push(dn);
    }
    LdapOperation::Modify { dn, changes } => {
      info!(dn = %dn, "Modifying entry");
      apply_changes(ldap, &dn, changes).await?;
      report.modified.push(dn);
    }
    LdapOperation::Rename {
      from_dn,
      to_dn,
      changes,
    } => {
      info!(from = %from_dn, to = %to_dn, "Renaming entry");
      let (new_rdn, new_parent) =
        split_rdn_parent(&to_dn).ok_or_else(|| {
          ProviderError::OperationFailed(format!(
            "rename target DN {:?} has no parent component",
            to_dn
          ))
        })?;
      let (_, from_parent) = split_rdn_parent(&from_dn).ok_or_else(|| {
        ProviderError::OperationFailed(format!(
          "rename source DN {:?} has no parent component",
          from_dn
        ))
      })?;
      // `new_sup` is only meaningful for a move between containers; when
      // the parents match we pass `None` so the server treats it as an
      // in-place rename.
      let new_sup = (new_parent != from_parent).then_some(new_parent);
      entry_modifydn(ldap, &from_dn, new_rdn, true, new_sup, &to_dn)
        .await
        .map_err(op_err)?;
      if !changes.is_empty() {
        apply_changes(ldap, &to_dn, changes).await?;
      }
      report.modified.push(to_dn);
    }
    LdapOperation::Delete { dn } => {
      info!(dn = %dn, "Deleting entry");
      entry_delete(ldap, &dn).await.map_err(op_err)?;
      report.deleted.push(dn);
    }
  }
  Ok(())
}

/// Applies a list of attribute-level changes (replace / delete) to
/// `dn`.  Shared between `Modify` and the post-modrdn follow-up of
/// `Rename`, both of which need exactly this dance.
async fn apply_changes(
  ldap: &mut Ldap,
  dn: &str,
  changes: Vec<LdapChange>,
) -> Result<(), ProviderError> {
  let owned: Vec<(String, Vec<String>, bool)> = changes
    .into_iter()
    .map(|c| match c {
      LdapChange::Replace { attr, values } => (attr, values, true),
      LdapChange::Delete { attr } => (attr, Vec::new(), false),
    })
    .collect();
  let mods: Vec<Mod<&str>> = owned
    .iter()
    .map(|(attr, values, is_replace)| {
      if *is_replace {
        let set: HashSet<&str> = values.iter().map(String::as_str).collect();
        Mod::Replace(attr.as_str(), set)
      } else {
        Mod::Delete(attr.as_str(), HashSet::new())
      }
    })
    .collect();
  entry_modify(ldap, dn, mods).await.map_err(op_err)
}

/// The search bases the provider owns.  Explicit bases come straight from
/// the configuration.  Otherwise every naming context the server publishes
/// is owned in full, minus the unmanaged ones, in a deterministic order.
async fn owned_bases(
  ldap: &mut Ldap,
  config: &ResolvedLdapConfig,
) -> Result<Vec<SearchBase>, OperationError> {
  match &config.ownership {
    Ownership::SearchBases(bases) => Ok(bases.clone()),
    Ownership::NamingContexts { unmanaged } => {
      naming_contexts(ldap).await.map(|contexts| {
        contexts
          .into_iter()
          .filter(|context| !unmanaged.iter().any(|u| same_dn(u, context)))
          .map(|context| (context.clone(), SearchBase::subtree(&context)))
          .collect::<BTreeMap<String, SearchBase>>()
          .into_values()
          .collect()
      })
    }
  }
}

/// Planning needs the owned bases to refuse entries outside them.  Explicit
/// bases need no connection; discovered ones are read from the server.
async fn bases_for_planning(
  config: &ResolvedLdapConfig,
) -> Result<Vec<SearchBase>, ProviderError> {
  match &config.ownership {
    Ownership::SearchBases(bases) => Ok(bases.clone()),
    Ownership::NamingContexts { .. } => {
      let mut ldap = connect(config).await?;
      owned_bases(&mut ldap, config).await.map_err(op_err)
    }
  }
}

/// Every entry one search base returns and covers.  Filtering by the same
/// predicate the runbook validates against keeps live state and the coverage
/// check from ever disagreeing.
async fn covered_entries(
  mut ldap: Ldap,
  base: &SearchBase,
) -> Result<Vec<(String, LiveAttrs)>, OperationError> {
  list_entries(&mut ldap, &base.base, base.scope.ldap_scope(), &base.filter)
    .await
    .map(|entries| {
      entries
        .into_iter()
        .filter(|(dn, _)| base.covers(dn))
        .collect()
    })
}

/// The live tree: every search base queried in parallel and folded into one
/// map keyed by DN.  `Ldap` is `Clone`; cloned handles share the connection
/// driver but can issue concurrent searches because ldap3 multiplexes
/// requests by message ID, so all bases run over one TCP connection.  The
/// map also deduplicates an entry that overlapping bases return twice.
async fn query_live(
  ldap: &Ldap,
  bases: &[SearchBase],
) -> Result<Value, OperationError> {
  try_join_all(bases.iter().map(|base| covered_entries(ldap.clone(), base)))
    .await
    .map(|per_base| live_tree(per_base.into_iter().flatten().collect()))
}

fn op_err(e: OperationError) -> ProviderError {
  ProviderError::OperationFailed(e.to_string())
}

fn runbook_err(e: RunbookError) -> ProviderError {
  ProviderError::OperationFailed(e.to_string())
}
