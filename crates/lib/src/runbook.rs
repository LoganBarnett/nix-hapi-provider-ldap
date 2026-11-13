//! Translates a wave's `DiffNode` forest into runbook steps and the
//! provider's internal `LdapOperation` representation, and refuses any
//! operation aimed at a DN the configured search bases do not own.

use crate::config::ResolvedLdapConfig;
use crate::dn::{dn_depth, rdn_of, split_rdn_parent};
use crate::search_base::SearchBase;
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

  #[error(
    "Rename DiffNode for {path:?} has an empty chain; the engine \
     guarantees length >= 2, so this indicates a malformed wave"
  )]
  EmptyRenameChain { path: String },

  #[error(
    "Rename DiffNode for {path:?} has a non-string chain entry; expected \
     an LDAP DN, got {value}"
  )]
  NonStringRenameEntry {
    path: String,
    value: serde_json::Value,
  },

  #[error(
    "Add for entry {dn:?} declares no objectClass; LDAP requires at least one \
     structural object class, so declare \"objectClass\" on the entry"
  )]
  AddMissingObjectClass { dn: String },

  #[error(
    "Add for entry {dn:?} has a DN whose leftmost component is not \
     \"attribute=value\""
  )]
  AddDnWithoutRdn { dn: String },

  #[error(
    "Entry {dn:?} is outside every configured search base {bases:?}; the \
     provider only manages the base entry of a \"base\" search, direct \
     children of a \"one\" search, or strict descendants of a \"sub\" search"
  )]
  DnOutsideSearchBases { dn: String, bases: Vec<String> },
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
  /// modrdn (LDAP modifyDN) for renames declared via providerKey
  /// history.  `from_dn` is the live DN we found the entry under;
  /// `to_dn` is the desired head DN.  `new_sup` is computed at
  /// apply-time from the two parent DNs: `None` when they match
  /// (in-place rename), `Some` when the entry also moves between
  /// containers.  `changes` are any non-rename field modifications
  /// the engine flagged for the same node; they apply to `to_dn`
  /// after the modrdn completes.
  Rename {
    from_dn: String,
    to_dn: String,
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
  bases: &[SearchBase],
) -> Result<Vec<RunbookStep>, RunbookError> {
  let ops = ensure_covered(
    changes
      .iter()
      .map(collect_ops)
      .collect::<Result<Vec<_>, _>>()?
      .into_iter()
      .flatten()
      .collect(),
    bases,
  )?;
  // Adds (parents before children), then renames + modifies (each
  // rename includes its own follow-up modify, so the two interleave
  // safely), then deletes (children before parents so the server
  // doesn't see orphans).  Renames sit before modifies because a
  // stale Modify targeting the same DN as an in-flight Rename would
  // race the modrdn; putting renames first keeps the wire ordering
  // robust even if a future caller passes a misordered DiffNode
  // forest.
  let (deletes, non_deletes): (Vec<_>, Vec<_>) = ops
    .into_iter()
    .partition(|op| matches!(op, LdapOperation::Delete { .. }));
  let (adds, rest): (Vec<_>, Vec<_>) = non_deletes
    .into_iter()
    .partition(|op| matches!(op, LdapOperation::Add { .. }));
  let (renames, modifies): (Vec<_>, Vec<_>) = rest
    .into_iter()
    .partition(|op| matches!(op, LdapOperation::Rename { .. }));
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
    .chain(renames)
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

/// Rejects any operation aimed at a DN outside the configured search bases.
/// Such an entry would be written but never read back as live, so every run
/// would plan it again.  Deletes are exempt: they come from live state, which
/// only ever holds covered entries.
fn ensure_covered(
  ops: Vec<LdapOperation>,
  bases: &[SearchBase],
) -> Result<Vec<LdapOperation>, RunbookError> {
  let outside = ops
    .iter()
    .flat_map(desired_dns)
    .find(|dn| !bases.iter().any(|base| base.covers(dn)))
    .map(str::to_string);
  match outside {
    None => Ok(ops),
    Some(dn) => Err(RunbookError::DnOutsideSearchBases {
      dn,
      bases: bases.iter().map(|base| base.url.clone()).collect(),
    }),
  }
}

/// The DNs an operation writes to, which are the ones that must be owned.
fn desired_dns(op: &LdapOperation) -> Vec<&str> {
  match op {
    LdapOperation::Add { dn, .. } | LdapOperation::Modify { dn, .. } => {
      vec![dn.as_str()]
    }
    LdapOperation::Rename { from_dn, to_dn, .. } => {
      vec![from_dn.as_str(), to_dn.as_str()]
    }
    LdapOperation::Delete { .. } => Vec::new(),
  }
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
      attrs: attrs_from_add(&node.field_changes, &dn)?,
    }),
    Status::Modify => {
      let changes = changes_from_modify(&node.field_changes, &dn);
      (!changes.is_empty()).then_some(LdapOperation::Modify {
        dn: dn.clone(),
        changes,
      })
    }
    Status::Delete => Some(LdapOperation::Delete { dn: dn.clone() }),
    Status::Rename { chain } => Some(LdapOperation::Rename {
      from_dn: dn_from_chain_entry(&node.path, chain.first(), 0)?,
      to_dn: dn.clone(),
      changes: changes_from_modify(&node.field_changes, &dn),
    }),
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

/// Pulls one DN out of a `Status::Rename` chain.  The engine
/// guarantees the chain is non-empty (length >= 2 in practice), but
/// the wire format is `Vec<Value>` so we have to range-check and
/// reject non-string entries.
fn dn_from_chain_entry(
  path: &str,
  entry: Option<&serde_json::Value>,
  _idx: usize,
) -> Result<String, RunbookError> {
  let entry = entry.ok_or_else(|| RunbookError::EmptyRenameChain {
    path: path.to_string(),
  })?;
  entry.as_str().map(String::from).ok_or_else(|| {
    RunbookError::NonStringRenameEntry {
      path: path.to_string(),
      value: entry.clone(),
    }
  })
}

/// Builds the attribute map for an Add from the declared fields.  The entry's
/// RDN attribute always carries its naming value: declared values of that
/// attribute (login aliases) are unioned with it, and when none are declared
/// it is seeded from the DN, since an entry without its naming value is a
/// namingViolation.  Attributes with no values are dropped because LDAP
/// cannot store them.  `objectClass` must be declared; the provider assumes
/// no schema and synthesises nothing else.
fn attrs_from_add(
  field_changes: &[FieldDiff],
  dn: &str,
) -> Result<BTreeMap<String, Vec<String>>, RunbookError> {
  let (rdn_attr, rdn_value) = rdn_of(dn)
    .ok_or_else(|| RunbookError::AddDnWithoutRdn { dn: dn.to_string() })?;
  let declared: BTreeMap<String, Vec<String>> = field_changes
    .iter()
    .filter_map(|c| field_target_values(&c.to).map(|v| (c.field.clone(), v)))
    .map(|(k, v)| match k.eq_ignore_ascii_case(rdn_attr) {
      true => (k, with_rdn_value(rdn_value, v)),
      false => (k, v),
    })
    .filter(|(_, v)| !v.is_empty())
    .collect();
  let naming = (!declared.keys().any(|k| k.eq_ignore_ascii_case(rdn_attr)))
    .then(|| (rdn_attr.to_string(), vec![rdn_value.to_string()]));
  let attrs: BTreeMap<String, Vec<String>> =
    naming.into_iter().chain(declared).collect();
  let has_object_class =
    attrs.keys().any(|k| k.eq_ignore_ascii_case("objectClass"));
  has_object_class
    .then_some(attrs)
    .ok_or_else(|| RunbookError::AddMissingObjectClass { dn: dn.to_string() })
}

/// Converts each `FieldDiff` in a Modify into a Replace (when a value
/// is present) or a per-attribute Delete (when the field was removed).
/// The entry's RDN attribute is the exception on both counts: its
/// naming value can be neither replaced away nor deleted, so a Replace
/// carries the RDN value ahead of the declared ones and a removal
/// becomes a Replace back to the RDN value alone.
fn changes_from_modify(
  field_changes: &[FieldDiff],
  dn: &str,
) -> Vec<LdapChange> {
  field_changes
    .iter()
    .map(|change| match (&change.to, rdn_of(dn)) {
      (FieldTarget::Value { value }, Some((attr, rdn_value)))
        if change.field.eq_ignore_ascii_case(attr) =>
      {
        LdapChange::Replace {
          attr: change.field.clone(),
          values: with_rdn_value(rdn_value, scalar_or_array_to_strings(value)),
        }
      }
      (FieldTarget::Removed, Some((attr, rdn_value)))
        if change.field.eq_ignore_ascii_case(attr) =>
      {
        LdapChange::Replace {
          attr: change.field.clone(),
          values: vec![rdn_value.to_string()],
        }
      }
      (FieldTarget::Value { value }, _) => LdapChange::Replace {
        attr: change.field.clone(),
        values: scalar_or_array_to_strings(value),
      },
      (FieldTarget::Removed, _) => LdapChange::Delete {
        attr: change.field.clone(),
      },
      (FieldTarget::DerivedPlaceholder { inputs }, _) => LdapChange::Replace {
        attr: change.field.clone(),
        values: vec![format_derived_display(inputs)],
      },
    })
    .collect()
}

/// `rdn_value` first, then every declared value that is not a repeat
/// of it; LDAP matches naming attributes case-insensitively, so so does
/// the dedup.
fn with_rdn_value(rdn_value: &str, declared: Vec<String>) -> Vec<String> {
  std::iter::once(rdn_value.to_string())
    .chain(
      declared
        .into_iter()
        .filter(|v| !v.eq_ignore_ascii_case(rdn_value)),
    )
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
/// elements are dropped; they have no LDAP representation.
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

/// Booleans take LDAP's own boolean syntax, matching what the Nix module
/// emits, so a declared `true` compares equal to the stored `TRUE`.
fn scalar_to_string(v: &serde_json::Value) -> Option<String> {
  match v {
    serde_json::Value::String(s) => Some(s.clone()),
    serde_json::Value::Number(n) => Some(n.to_string()),
    serde_json::Value::Bool(true) => Some("TRUE".to_string()),
    serde_json::Value::Bool(false) => Some("FALSE".to_string()),
    _ => None,
  }
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
    LdapOperation::Rename {
      from_dn,
      to_dn,
      changes,
    } => RunbookStep {
      description: format!("rename {} -> {}", from_dn, to_dn),
      command: format!("ldapmodrdn {}", connect_args),
      body: Some(ldif_modrdn(from_dn, to_dn, changes)),
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

/// LDIF doesn't have a single grammar for "modrdn + follow-up
/// modify", so the body is a human-readable two-section block: the
/// modrdn line(s) first, then a divider and the standard
/// `changetype: modify` LDIF for any follow-up field changes.  The
/// operator can spot-check both halves before applying.
fn ldif_modrdn(from_dn: &str, to_dn: &str, changes: &[LdapChange]) -> String {
  let new_rdn = split_rdn_parent(to_dn).map(|(rdn, _)| rdn).unwrap_or(to_dn);
  let modrdn_block = [
    format!("dn: {}", from_dn),
    "changetype: modrdn".to_string(),
    format!("newrdn: {}", new_rdn),
    "deleteoldrdn: 1".to_string(),
  ]
  .into_iter()
  .chain(
    split_rdn_parent(to_dn)
      .zip(split_rdn_parent(from_dn))
      .filter(|((_, to_parent), (_, from_parent))| to_parent != from_parent)
      .map(|((_, to_parent), _)| format!("newsuperior: {}", to_parent)),
  )
  .collect::<Vec<_>>()
  .join("\n");

  // No field changes: just the modrdn block.
  if changes.is_empty() {
    return modrdn_block;
  }
  [modrdn_block, ldif_modify(to_dn, changes)].join("\n\n")
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

fn format_derived_display(inputs: &BTreeMap<String, String>) -> String {
  let parts: Vec<String> = inputs
    .iter()
    .map(|(alias, path)| format!("{}={}", alias, path))
    .collect();
  format!("<derived from {}>", parts.join(", "))
}
