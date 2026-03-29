use crate::config::ResolvedLdapConfig;
use crate::connection::connect;
use crate::desired_state::LdapDesiredState;
use crate::live_state::LdapLiveState;
use crate::operations::{
  entry_add, entry_delete, entry_get, entry_list, entry_modify, OperationError,
};
use crate::reconcile::{diff, ou_groups_dn, ou_users_dn, ReconcileError};
use crate::runbook::{to_runbook_steps, LdapOperation};
use ldap3::Mod;
use nix_hapi_lib::meta::NixHapiMeta;
use nix_hapi_lib::plan::{ApplyReport, ProviderPlan};
use nix_hapi_lib::provider::{Filter, Provider, ProviderError, ResolvedConfig};
use regex::Regex;
use std::collections::HashSet;
use tracing::info;

pub struct LdapProvider;

impl Provider for LdapProvider {
  fn provider_type(&self) -> &str {
    "ldap"
  }

  fn sensitive_config_fields(&self) -> &[&str] {
    &["bindPassword"]
  }

  fn list_live(
    &self,
    config: &ResolvedConfig,
    _filters: &[Filter],
  ) -> Result<serde_json::Value, ProviderError> {
    let ldap_config = ResolvedLdapConfig::from_resolved_config(config)?;
    let mut ldap = connect(&ldap_config)?;

    let live = query_live_state(&mut ldap, &ldap_config)
      .map_err(|e| ProviderError::OperationFailed(e.to_string()))?;

    serde_json::to_value(&live)
      .map_err(|e| ProviderError::LiveStateParse(e.to_string()))
  }

  fn plan(
    &self,
    desired: &serde_json::Value,
    live: &serde_json::Value,
    meta: &NixHapiMeta,
    config: &ResolvedConfig,
  ) -> Result<ProviderPlan, ProviderError> {
    let ldap_config = ResolvedLdapConfig::from_resolved_config(config)?;

    let desired_state: LdapDesiredState =
      serde_json::from_value(desired.clone())
        .map_err(|e| ProviderError::DesiredStateParse(e.to_string()))?;

    let live_state: LdapLiveState = serde_json::from_value(live.clone())
      .map_err(|e| ProviderError::LiveStateParse(e.to_string()))?;

    let ignore_patterns = compile_ignore_patterns(&meta.ignore)?;

    let ldap_diff =
      diff(&desired_state, &live_state, &ldap_config.base_dn, &ignore_patterns)
        .map_err(|e: ReconcileError| {
          ProviderError::OperationFailed(e.to_string())
        })?;

    let runbook = to_runbook_steps(&ldap_diff, &ldap_config);

    Ok(ProviderPlan {
      instance_name: String::new(), // filled in by the CLI dispatcher
      provider_type: self.provider_type().to_string(),
      changes: ldap_diff.resource_changes,
      runbook,
    })
  }

  fn apply(
    &self,
    plan: &ProviderPlan,
    config: &ResolvedConfig,
  ) -> Result<ApplyReport, ProviderError> {
    let ldap_config = ResolvedLdapConfig::from_resolved_config(config)?;
    let mut ldap = connect(&ldap_config)?;
    let mut report = ApplyReport::default();

    for step in &plan.runbook {
      let op: LdapOperation = serde_json::from_value(step.operation.clone())
        .map_err(|e| {
          ProviderError::OperationFailed(format!(
            "Failed to deserialise operation for '{}': {}",
            step.description, e
          ))
        })?;

      match op {
        LdapOperation::Add { dn, attrs } => {
          info!(dn = %dn, "Adding entry");
          let owned: Vec<(String, HashSet<String>)> = attrs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
          let borrowed: Vec<(&str, HashSet<&str>)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.iter().map(|s| s.as_str()).collect()))
            .collect();
          entry_add(&mut ldap, &dn, borrowed).map_err(op_err)?;
          report.created.push(dn);
        }
        LdapOperation::Modify { dn, changes } => {
          info!(dn = %dn, "Modifying entry");
          let owned: Vec<(String, Vec<String>, bool)> = changes
            .into_iter()
            .map(|c| match c {
              crate::runbook::LdapChange::Add { attr, values } => {
                (attr, values, false)
              }
              crate::runbook::LdapChange::Replace { attr, values } => {
                (attr, values, true)
              }
            })
            .collect();
          let mods: Vec<Mod<&str>> = owned
            .iter()
            .map(|(attr, values, is_replace)| {
              let set: HashSet<&str> =
                values.iter().map(|s| s.as_str()).collect();
              if *is_replace {
                Mod::Replace(attr.as_str(), set)
              } else {
                Mod::Add(attr.as_str(), set)
              }
            })
            .collect();
          entry_modify(&mut ldap, &dn, mods).map_err(op_err)?;
          report.modified.push(dn);
        }
        LdapOperation::Delete { dn } => {
          info!(dn = %dn, "Deleting entry");
          entry_delete(&mut ldap, &dn).map_err(op_err)?;
          report.deleted.push(dn);
        }
      }
    }

    Ok(report)
  }
}

/// Queries the live LDAP state for users and groups.
fn query_live_state(
  ldap: &mut ldap3::LdapConn,
  config: &ResolvedLdapConfig,
) -> Result<LdapLiveState, OperationError> {
  let mut state = LdapLiveState::default();

  let users_base = ou_users_dn(&config.base_dn);
  let groups_base = ou_groups_dn(&config.base_dn);

  // Users: one-level search under ou=users.
  let user_dns = entry_list(ldap, &users_base)?;
  for dn in user_dns {
    if dn == users_base {
      continue; // skip the OU entry itself
    }
    if let Some(attrs) = entry_get(ldap, &dn)? {
      // Extract uid from the DN (uid=alice,ou=users,...) → "alice".
      if let Some(uid) = rdn_value(&dn, "uid") {
        state.users.insert(uid, attrs);
      }
    }
  }

  // Groups: one-level search under ou=groups.
  let group_dns = entry_list(ldap, &groups_base)?;
  for dn in group_dns {
    if dn == groups_base {
      continue;
    }
    if let Some(attrs) = entry_get(ldap, &dn)? {
      if let Some(cn) = rdn_value(&dn, "cn") {
        state.groups.insert(cn, attrs);
      }
    }
  }

  Ok(state)
}

/// Extracts the value of a named RDN component from a DN string.
/// e.g. `rdn_value("uid=alice,ou=users,dc=proton,dc=org", "uid")` → `Some("alice")`.
fn rdn_value(dn: &str, attr: &str) -> Option<String> {
  dn.split(',').next().and_then(|rdn| {
    let (k, v) = rdn.split_once('=')?;
    (k.trim().eq_ignore_ascii_case(attr)).then(|| v.trim().to_string())
  })
}

fn compile_ignore_patterns(
  patterns: &[String],
) -> Result<Vec<Regex>, ProviderError> {
  patterns
    .iter()
    .map(|p| {
      Regex::new(p).map_err(|e| {
        ProviderError::OperationFailed(format!(
          "Invalid ignore pattern {:?}: {}",
          p, e
        ))
      })
    })
    .collect()
}

fn op_err(e: OperationError) -> ProviderError {
  ProviderError::OperationFailed(e.to_string())
}
