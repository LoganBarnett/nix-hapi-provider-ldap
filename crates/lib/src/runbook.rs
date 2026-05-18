//! Translates a wave's `DiffNode` forest into runbook steps and the
//! provider's internal `LdapOperation` representation.

use crate::config::ResolvedLdapConfig;
use nix_hapi_lib::plan::{
  DiffNode, FieldDiff, FieldTarget, RunbookStep, Status,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunbookError {
  #[error("DiffNode for {path:?} has an empty providerKey")]
  EmptyProviderKey { path: String },

  #[error(
    "DiffNode for {path:?} has a non-string providerKey head; expected an \
     LDAP DN, got {value}"
  )]
  NonStringProviderKey {
    path: String,
    value: serde_json::Value,
  },

  #[error("Rename support is not implemented yet (path={path:?})")]
  RenameUnsupported { path: String },
}

/// Machine-executable representation of an LDAP operation, serialised
/// into `RunbookStep.operation`.  Resurrected from the operation field
/// on `apply` so the provider can replay what it planned.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum LdapOperation {
  Add {
    dn: String,
    attrs: BTreeMap<String, Vec<String>>,
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
  Replace { attr: String, values: Vec<String> },
  Delete { attr: String },
}

/// Converts a wave's `DiffNode` forest into runbook steps in the
/// natural order of the wave (top-down for adds/modifies; deletes are
/// reordered so children precede parents to keep LDAP happy).
pub fn to_runbook_steps(
  changes: &[DiffNode],
  config: &ResolvedLdapConfig,
) -> Result<Vec<RunbookStep>, RunbookError> {
  let ops: Vec<LdapOperation> = changes
    .iter()
    .map(collect_ops)
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .flatten()
    .collect();
  // Adds first, then modifies, then deletes (children before parents).
  let (deletes, non_deletes): (Vec<_>, Vec<_>) = ops
    .into_iter()
    .partition(|op| matches!(op, LdapOperation::Delete { .. }));
  let (adds, modifies): (Vec<_>, Vec<_>) = non_deletes
    .into_iter()
    .partition(|op| matches!(op, LdapOperation::Add { .. }));
  let adds = sorted_by_key(adds, |op| match op {
    LdapOperation::Add { dn, .. } => dn_depth(dn),
    _ => 0,
  });
  let deletes = sorted_by_key(deletes, |op| match op {
    LdapOperation::Delete { dn } => std::cmp::Reverse(dn_depth(dn)),
    _ => std::cmp::Reverse(0),
  });

  let connect_args = scrubbed_connect_args(config);
  adds
    .into_iter()
    .chain(modifies)
    .chain(deletes)
    .map(|op| operation_to_step(op, &connect_args))
    .collect()
}

/// `Vec::sort_by_key` mutates in place and returns `()`; this is the
/// equivalent expression-shaped form that yields a sorted owned vec
/// so callers can stay in chain-land.
fn sorted_by_key<T, K: Ord>(mut v: Vec<T>, key: impl FnMut(&T) -> K) -> Vec<T> {
  v.sort_by_key(key);
  v
}

/// Produces the flat list of LDAP operations for one diff subtree
/// (the node itself plus everything underneath it).  An empty
/// `Modify` is elided since `entry_modify` with no mods is a no-op
/// the server would reject anyway.
fn collect_ops(node: &DiffNode) -> Result<Vec<LdapOperation>, RunbookError> {
  let dn = dn_from_node(node)?;
  let own_op = match &node.status {
    Status::Add => Some(LdapOperation::Add {
      dn: dn.clone(),
      attrs: attrs_from_add(&node.field_changes, &dn),
    }),
    Status::Modify => {
      let changes = changes_from_modify(&node.field_changes);
      (!changes.is_empty()).then_some(LdapOperation::Modify {
        dn: dn.clone(),
        changes,
      })
    }
    Status::Delete => Some(LdapOperation::Delete { dn: dn.clone() }),
    Status::Rename { .. } => {
      return Err(RunbookError::RenameUnsupported {
        path: node.path.clone(),
      });
    }
  };
  let child_ops = node
    .children
    .iter()
    .map(collect_ops)
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .flatten();
  Ok(own_op.into_iter().chain(child_ops).collect())
}

/// Extracts the LDAP DN this node addresses (the providerKey head).
fn dn_from_node(node: &DiffNode) -> Result<String, RunbookError> {
  let head = node.provider_key.first().ok_or_else(|| {
    RunbookError::EmptyProviderKey {
      path: node.path.clone(),
    }
  })?;
  head.as_str().map(String::from).ok_or_else(|| {
    RunbookError::NonStringProviderKey {
      path: node.path.clone(),
      value: head.clone(),
    }
  })
}

/// Builds the full attribute map for an Add by layering the user's
/// declared fields on top of the DN-derived defaults (objectClass +
/// RDN attribute, plus the groupOfNames `member` placeholder when
/// relevant).  `BTreeMap::from_iter` is last-write-wins, so defaults
/// must come first in the chain for user values to override them.
/// An empty user-declared `member` does *not* override the placeholder
/// — groupOfNames forbids zero-member entries.
fn attrs_from_add(
  field_changes: &[FieldDiff],
  dn: &str,
) -> BTreeMap<String, Vec<String>> {
  let user_attrs = field_changes
    .iter()
    .filter_map(|c| field_target_values(&c.to).map(|v| (c.field.clone(), v)))
    .filter(|(k, v)| !(k == "member" && v.is_empty()));
  defaults_for_dn(dn).into_iter().chain(user_attrs).collect()
}

/// Converts each `FieldDiff` in a Modify into a Replace (when a value
/// is present) or a per-attribute Delete (when the field was removed).
fn changes_from_modify(field_changes: &[FieldDiff]) -> Vec<LdapChange> {
  field_changes
    .iter()
    .map(|change| match &change.to {
      FieldTarget::Value { value } => LdapChange::Replace {
        attr: change.field.clone(),
        values: scalar_or_array_to_strings(value),
      },
      FieldTarget::Removed => LdapChange::Delete {
        attr: change.field.clone(),
      },
      FieldTarget::DerivedPlaceholder { inputs } => LdapChange::Replace {
        attr: change.field.clone(),
        values: vec![format_derived_display(inputs)],
      },
    })
    .collect()
}

fn field_target_values(target: &FieldTarget) -> Option<Vec<String>> {
  match target {
    FieldTarget::Value { value } => Some(scalar_or_array_to_strings(value)),
    FieldTarget::Removed => None,
    FieldTarget::DerivedPlaceholder { inputs } => {
      Some(vec![format_derived_display(inputs)])
    }
  }
}

/// Coerces a `serde_json::Value` to the LDAP attribute-value vector
/// representation: arrays expand to their elements, scalars become a
/// single-element vector, null becomes empty.  Non-scalar array
/// elements are dropped — they have no LDAP representation.
fn scalar_or_array_to_strings(value: &serde_json::Value) -> Vec<String> {
  match value {
    serde_json::Value::Array(arr) => {
      arr.iter().filter_map(scalar_to_string).collect()
    }
    serde_json::Value::Null => Vec::new(),
    serde_json::Value::Object(_) => Vec::new(),
    other => scalar_to_string(other).map(|s| vec![s]).unwrap_or_default(),
  }
}

fn scalar_to_string(v: &serde_json::Value) -> Option<String> {
  match v {
    serde_json::Value::String(s) => Some(s.clone()),
    serde_json::Value::Number(n) => Some(n.to_string()),
    serde_json::Value::Bool(b) => Some(b.to_string()),
    _ => None,
  }
}

/// Synthesises the entry-type-driven default attributes for an Add:
/// objectClass, the RDN attribute (uid / cn), and (for groups) the
/// groupOfNames `member` placeholder.  User-declared field changes
/// layer on top of these in `attrs_from_add`; the only quirk is that
/// an empty user-declared `member` is filtered out so the placeholder
/// wins (groupOfNames forbids zero-member entries).
///
/// Returning a fresh map per call keeps the builder pure — no
/// `&mut`-threading, no `entry().or_insert_with()` ceremony.
fn defaults_for_dn(dn: &str) -> BTreeMap<String, Vec<String>> {
  if dn.starts_with("uid=") {
    let object_class = (
      "objectClass".to_string(),
      vec![
        "inetOrgPerson".to_string(),
        "organizationalPerson".to_string(),
        "person".to_string(),
        "top".to_string(),
      ],
    );
    let uid =
      crate::dn::rdn_value(dn, "uid").map(|u| ("uid".to_string(), vec![u]));
    std::iter::once(object_class).chain(uid).collect()
  } else if dn.starts_with("cn=") {
    let object_class = (
      "objectClass".to_string(),
      vec!["groupOfNames".to_string(), "top".to_string()],
    );
    let cn =
      crate::dn::rdn_value(dn, "cn").map(|c| ("cn".to_string(), vec![c]));
    let placeholder_member = strip_rdn(dn, "cn").map(|suffix| {
      (
        "member".to_string(),
        vec![format!("uid=placeholder,ou=users,{}", suffix)],
      )
    });
    std::iter::once(object_class)
      .chain(cn)
      .chain(placeholder_member)
      .collect()
  } else {
    BTreeMap::new()
  }
}

fn strip_rdn<'a>(dn: &'a str, expected_attr: &str) -> Option<&'a str> {
  let (rdn, rest) = dn.split_once(',')?;
  let (attr, _) = rdn.split_once('=')?;
  if !attr.trim().eq_ignore_ascii_case(expected_attr) {
    return None;
  }
  let (ou, rest) = rest.split_once(',')?;
  if !ou.trim().to_ascii_lowercase().starts_with("ou=") {
    return None;
  }
  Some(rest)
}

fn operation_to_step(
  op: LdapOperation,
  connect_args: &str,
) -> Result<RunbookStep, RunbookError> {
  let step = match &op {
    LdapOperation::Add { dn, attrs } => RunbookStep {
      description: format!("add {}", dn),
      command: format!("ldapadd {}", connect_args),
      body: Some(ldif_add(dn, attrs)),
      operation: serde_json::to_value(&op).unwrap_or(serde_json::Value::Null),
    },
    LdapOperation::Modify { dn, changes } => RunbookStep {
      description: format!("modify {}", dn),
      command: format!("ldapmodify {}", connect_args),
      body: Some(ldif_modify(dn, changes)),
      operation: serde_json::to_value(&op).unwrap_or(serde_json::Value::Null),
    },
    LdapOperation::Delete { dn } => RunbookStep {
      description: format!("delete {}", dn),
      command: format!("ldapdelete {} \"{}\"", connect_args, dn),
      body: None,
      operation: serde_json::to_value(&op).unwrap_or(serde_json::Value::Null),
    },
  };
  Ok(step)
}

fn scrubbed_connect_args(config: &ResolvedLdapConfig) -> String {
  format!("-H \"{}\" -D \"{}\" -w ***", config.url, config.bind_dn)
}

fn ldif_add(dn: &str, attrs: &BTreeMap<String, Vec<String>>) -> String {
  let header = [format!("dn: {}", dn), "changetype: add".to_string()];
  let body = attrs.iter().flat_map(|(attr, values)| {
    values.iter().map(move |v| format!("{}: {}", attr, v))
  });
  header
    .into_iter()
    .chain(body)
    .collect::<Vec<_>>()
    .join("\n")
}

fn ldif_modify(dn: &str, changes: &[LdapChange]) -> String {
  // Each change is one LDIF block (a multi-line string); adjacent
  // blocks are separated by a `-` line per the LDIF modify grammar.
  // `Vec::join("\n-\n")` does the intersperse for us.  When `changes`
  // is empty the body is `None` and `chain(body)` skips it so there is
  // no trailing newline.
  let body = (!changes.is_empty()).then(|| {
    changes
      .iter()
      .map(change_to_ldif_block)
      .collect::<Vec<_>>()
      .join("\n-\n")
  });
  [format!("dn: {}", dn), "changetype: modify".to_string()]
    .into_iter()
    .chain(body)
    .collect::<Vec<_>>()
    .join("\n")
}

fn change_to_ldif_block(change: &LdapChange) -> String {
  match change {
    LdapChange::Replace { attr, values } => {
      std::iter::once(format!("replace: {}", attr))
        .chain(values.iter().map(|v| format!("{}: {}", attr, v)))
        .collect::<Vec<_>>()
        .join("\n")
    }
    LdapChange::Delete { attr } => format!("delete: {}", attr),
  }
}

fn dn_depth(dn: &str) -> usize {
  dn.split(',').count()
}

fn format_derived_display(inputs: &BTreeMap<String, String>) -> String {
  let parts: Vec<String> = inputs
    .iter()
    .map(|(alias, path)| format!("{}={}", alias, path))
    .collect();
  format!("<derived from {}>", parts.join(", "))
}
