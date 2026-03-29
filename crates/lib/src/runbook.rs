use crate::config::ResolvedLdapConfig;
use crate::reconcile::{AttrModOp, LdapDiff};
use nix_hapi_lib::plan::RunbookStep;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Machine-executable representation of an LDAP operation, serialised into
/// `RunbookStep.operation`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum LdapOperation {
  Add {
    dn: String,
    attrs: HashMap<String, Vec<String>>,
  },
  Modify {
    dn: String,
    changes: Vec<LdapChange>,
  },
  Delete {
    dn: String,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum LdapChange {
  Add { attr: String, values: Vec<String> },
  Replace { attr: String, values: Vec<String> },
}

/// Converts a `LdapDiff` into `RunbookStep`s in the natural output order of
/// the diff (adds, then modifies, then deletes).
pub fn to_runbook_steps(
  diff: &LdapDiff,
  config: &ResolvedLdapConfig,
) -> Vec<RunbookStep> {
  let connect_args = scrubbed_connect_args(config);
  let mut steps = Vec::new();

  for (dn, attrs) in &diff.to_add {
    let operation = LdapOperation::Add {
      dn: dn.clone(),
      attrs: attrs.clone(),
    };
    let body = ldif_add(dn, attrs);
    steps.push(RunbookStep {
      description: format!("add {}", dn),
      command: format!("ldapadd {}", connect_args),
      body: Some(body),
      operation: serde_json::to_value(&operation).unwrap(),
    });
  }

  for (dn, mods) in &diff.to_modify {
    let changes: Vec<LdapChange> = mods
      .iter()
      .map(|m| match m.op {
        AttrModOp::Add => LdapChange::Add {
          attr: m.attr.clone(),
          values: m.values.clone(),
        },
        AttrModOp::Replace => LdapChange::Replace {
          attr: m.attr.clone(),
          values: m.values.clone(),
        },
      })
      .collect();
    let operation = LdapOperation::Modify {
      dn: dn.clone(),
      changes: changes.clone(),
    };
    let body = ldif_modify(dn, &changes);
    steps.push(RunbookStep {
      description: format!("modify {}", dn),
      command: format!("ldapmodify {}", connect_args),
      body: Some(body),
      operation: serde_json::to_value(&operation).unwrap(),
    });
  }

  for dn in &diff.to_delete {
    let operation = LdapOperation::Delete { dn: dn.clone() };
    steps.push(RunbookStep {
      description: format!("delete {}", dn),
      command: format!("ldapdelete {} \"{}\"", connect_args, dn),
      body: None,
      operation: serde_json::to_value(&operation).unwrap(),
    });
  }

  steps
}

fn scrubbed_connect_args(config: &ResolvedLdapConfig) -> String {
  format!("-H \"{}\" -D \"{}\" -w ***", config.url, config.bind_dn)
}

fn ldif_add(dn: &str, attrs: &HashMap<String, Vec<String>>) -> String {
  let mut lines = vec![format!("dn: {}", dn), "changetype: add".to_string()];
  let mut sorted_attrs: Vec<(&String, &Vec<String>)> = attrs.iter().collect();
  sorted_attrs.sort_by_key(|(k, _)| k.as_str());
  for (attr, values) in sorted_attrs {
    for value in values {
      lines.push(format!("{}: {}", attr, value));
    }
  }
  lines.join("\n")
}

fn ldif_modify(dn: &str, changes: &[LdapChange]) -> String {
  let mut lines = vec![format!("dn: {}", dn), "changetype: modify".to_string()];
  for (i, change) in changes.iter().enumerate() {
    if i > 0 {
      lines.push("-".to_string());
    }
    match change {
      LdapChange::Add { attr, values } => {
        lines.push(format!("add: {}", attr));
        for v in values {
          lines.push(format!("{}: {}", attr, v));
        }
      }
      LdapChange::Replace { attr, values } => {
        lines.push(format!("replace: {}", attr));
        for v in values {
          lines.push(format!("{}: {}", attr, v));
        }
      }
    }
  }
  lines.join("\n")
}
