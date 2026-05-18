use crate::config::ResolvedLdapConfig;
use crate::connection::connect;
use crate::dn::{ou_groups_dn, ou_users_dn};
use crate::live::{
  group_key_from_dn, group_to_json, user_key_from_dn, user_to_json,
};
use crate::operations::{
  entry_add, entry_delete, entry_modify, list_entries, OperationError,
};
use crate::runbook::{
  to_runbook_steps, LdapChange, LdapOperation, RunbookError,
};
use async_trait::async_trait;
use ldap3::{Ldap, Mod};
use nix_hapi_lib::meta::NixHapiMeta;
use nix_hapi_lib::plan::{ApplyReport, ProviderPlanWave, RunbookStep};
use nix_hapi_lib::provider::{Filter, Provider, ProviderError, ResolvedConfig};
use serde_json::{Map, Value};
use std::collections::HashSet;
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
    query_live(&mut ldap, &ldap_config)
      .await
      .map_err(|e| ProviderError::OperationFailed(e.to_string()))
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
    to_runbook_steps(&wave.changes, &ldap_config).map_err(runbook_err)
  }

  async fn apply(
    &self,
    wave: &ProviderPlanWave,
    config: &ResolvedConfig,
  ) -> Result<ApplyReport, ProviderError> {
    let ldap_config = ResolvedLdapConfig::from_resolved_config(config)?;
    let mut ldap = connect(&ldap_config).await?;
    let mut report = ApplyReport::default();

    let steps =
      to_runbook_steps(&wave.changes, &ldap_config).map_err(runbook_err)?;
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
            let set: HashSet<&str> =
              values.iter().map(String::as_str).collect();
            Mod::Replace(attr.as_str(), set)
          } else {
            Mod::Delete(attr.as_str(), HashSet::new())
          }
        })
        .collect();
      entry_modify(ldap, &dn, mods).await.map_err(op_err)?;
      report.modified.push(dn);
    }
    LdapOperation::Delete { dn } => {
      info!(dn = %dn, "Deleting entry");
      entry_delete(ldap, &dn).await.map_err(op_err)?;
      report.deleted.push(dn);
    }
  }
  Ok(())
}

async fn query_live(
  ldap: &mut Ldap,
  config: &ResolvedLdapConfig,
) -> Result<Value, OperationError> {
  // `Ldap` is `Clone`; cloned handles share the connection driver but
  // can issue concurrent searches because ldap3 multiplexes requests
  // by message ID.  So the two base queries genuinely run in parallel
  // over the same TCP connection.
  let users_base = ou_users_dn(&config.base_dn);
  let groups_base = ou_groups_dn(&config.base_dn);
  let mut ldap_users = ldap.clone();
  let mut ldap_groups = ldap.clone();
  let (user_entries, group_entries) = tokio::try_join!(
    list_entries(&mut ldap_users, &users_base),
    list_entries(&mut ldap_groups, &groups_base),
  )?;

  let users = entries_to_object(
    user_entries,
    |dn| user_key_from_dn(dn),
    |k, attrs| user_to_json(k, &config.base_dn, attrs),
  );
  let groups = entries_to_object(
    group_entries,
    |dn| group_key_from_dn(dn),
    |k, attrs| group_to_json(k, &config.base_dn, attrs),
  );

  Ok(serde_json::json!({
    "users": Value::Object(users),
    "groups": Value::Object(groups),
  }))
}

/// Folds a list of `(dn, attrs)` pairs into a JSON object keyed by
/// whatever `extract_key` derives from the DN (uid for users, cn for
/// groups).  Entries whose DN doesn't yield a key are skipped — those
/// are not entries this provider owns.
fn entries_to_object(
  entries: Vec<(String, std::collections::HashMap<String, Vec<String>>)>,
  extract_key: impl Fn(&str) -> Option<String>,
  to_json: impl Fn(&str, &std::collections::HashMap<String, Vec<String>>) -> Value,
) -> Map<String, Value> {
  entries
    .into_iter()
    .filter_map(|(dn, attrs)| {
      extract_key(&dn).map(|key| {
        let json = to_json(&key, &attrs);
        (key, json)
      })
    })
    .collect()
}

fn op_err(e: OperationError) -> ProviderError {
  ProviderError::OperationFailed(e.to_string())
}

fn runbook_err(e: RunbookError) -> ProviderError {
  ProviderError::OperationFailed(e.to_string())
}
