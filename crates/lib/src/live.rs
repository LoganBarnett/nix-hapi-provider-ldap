//! Builds the live-state JSON tree the engine consumes.
//!
//! The shape mirrors what the Nix module emits for desired state so the
//! engine's diff has matching structure on both sides:
//!
//! ```json
//! {
//!   "users":  { "<uid>": { "__nixhapi": { "providerKey": ["<dn>"] }, ... } },
//!   "groups": { "<cn>":  { "__nixhapi": { "providerKey": ["<dn>"] }, ... } }
//! }
//! ```
//!
//! Per-entry attribute values are normalised so structural equality
//! against the user's declared values produces the intended diffs:
//!
//! - Single-valued attributes become JSON scalars rather than
//!   one-element arrays.
//! - Multi-valued attributes are sorted lexicographically so set
//!   semantics survive a strict-equality compare.
//! - Attributes the engine should not see — the entry's RDN attribute
//!   (`uid` / `cn`-of-group) and `objectClass` — are filtered out.  They
//!   are implicit in the providerKey and re-synthesised by the provider
//!   on Add operations.

use crate::dn::{group_dn, rdn_value, user_dn};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

pub type LiveAttrs = HashMap<String, Vec<String>>;

/// Builds the per-user JSON object the engine diffs against.  `uid` is
/// the entry's RDN value (the Nix attrset key); `base_dn` lets us
/// compose the providerKey DN.
pub fn user_to_json(uid: &str, base_dn: &str, attrs: &LiveAttrs) -> Value {
  let mut obj = Map::new();
  obj.insert(
    "__nixhapi".to_string(),
    json!({ "providerKey": [user_dn(uid, base_dn)] }),
  );
  insert_normalised_attrs(&mut obj, attrs, "uid");
  Value::Object(obj)
}

/// Builds the per-group JSON object the engine diffs against.  `cn`
/// is the entry's RDN value (the Nix attrset key).
pub fn group_to_json(cn: &str, base_dn: &str, attrs: &LiveAttrs) -> Value {
  let mut obj = Map::new();
  obj.insert(
    "__nixhapi".to_string(),
    json!({ "providerKey": [group_dn(cn, base_dn)] }),
  );
  insert_normalised_attrs(&mut obj, attrs, "cn");
  Value::Object(obj)
}

/// Returns the RDN attribute name and the JSON key (uid/cn value) for
/// a live DN under the conventional users/groups OUs.  Returns `None`
/// when the DN doesn't carry a recognisable RDN.
pub fn user_key_from_dn(dn: &str) -> Option<String> {
  rdn_value(dn, "uid")
}

pub fn group_key_from_dn(dn: &str) -> Option<String> {
  rdn_value(dn, "cn")
}

/// Adds each non-hidden attribute to `out`, converting single-valued
/// attributes to scalars and sorting multi-valued ones.  `rdn_attr`
/// (the entry's RDN attribute, e.g. `uid`) and `objectClass` are
/// elided — they are provider-managed and not part of the diff.
fn insert_normalised_attrs(
  out: &mut Map<String, Value>,
  attrs: &LiveAttrs,
  rdn_attr: &str,
) {
  for (k, values) in attrs {
    if k.eq_ignore_ascii_case(rdn_attr) || k.eq_ignore_ascii_case("objectClass")
    {
      continue;
    }
    out.insert(k.clone(), normalise(values));
  }
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
