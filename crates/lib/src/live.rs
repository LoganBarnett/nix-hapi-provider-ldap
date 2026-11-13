//! Builds the live-state JSON tree the engine consumes.
//!
//! The shape is a flat map keyed by DN, the same shape the Nix module emits
//! for desired state, so the engine's diff has matching structure on both
//! sides and Delete paths (which follow live) land where `ignore` and
//! `derivedFrom` expressions written against desired expect them:
//!
//! ```json
//! { "entries": { "<dn>": { "__nixhapi": { "providerKey": ["<dn>"] }, ... } } }
//! ```
//!
//! Per-entry attribute values are normalised so structural equality against
//! the declared values produces the intended diffs:
//!
//! - Single-valued attributes become JSON scalars rather than one-element
//!   arrays.
//! - Multi-valued attributes are sorted lexicographically so set semantics
//!   survive a strict-equality compare.
//! - The RDN value is dropped from the entry's RDN attribute.  It is implicit
//!   in the DN and re-synthesised on Add; further values of that attribute
//!   stay visible, so declared login aliases diff cleanly.  `objectClass` is
//!   an ordinary attribute here, because the provider assumes no schema.

use crate::dn::rdn_of;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

pub type LiveAttrs = HashMap<String, Vec<String>>;

/// The whole live tree for a scope, keyed by DN as the server returned it.
pub fn live_tree(entries: BTreeMap<String, LiveAttrs>) -> Value {
  json!({
    "entries": entries
      .iter()
      .map(|(dn, attrs)| (dn.clone(), entry_to_json(dn, attrs)))
      .collect::<Map<String, Value>>(),
  })
}

/// One entry as the engine diffs it.  The RDN attribute is matched
/// case-insensitively, as is the RDN value within it, because LDAP matches
/// the naming attributes this provider meets that way.
pub fn entry_to_json(dn: &str, attrs: &LiveAttrs) -> Value {
  let rdn = rdn_of(dn);
  std::iter::once(("__nixhapi".to_string(), json!({ "providerKey": [dn] })))
    .chain(attrs.iter().filter_map(|(attr, values)| {
      let visible: Vec<String> = match rdn {
        Some((rdn_attr, rdn_value)) if attr.eq_ignore_ascii_case(rdn_attr) => {
          values
            .iter()
            .filter(|v| !v.eq_ignore_ascii_case(rdn_value))
            .cloned()
            .collect()
        }
        _ => values.clone(),
      };
      (!visible.is_empty()).then(|| (attr.clone(), normalise(&visible)))
    }))
    .collect::<Map<String, Value>>()
    .into()
}

fn normalise(values: &[String]) -> Value {
  match values.len() {
    0 => Value::Null,
    1 => Value::String(values[0].clone()),
    _ => {
      let mut sorted = values.to_vec();
      sorted.sort();
      Value::Array(sorted.into_iter().map(Value::String).collect())
    }
  }
}
