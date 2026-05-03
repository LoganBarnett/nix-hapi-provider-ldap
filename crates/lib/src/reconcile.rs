use crate::desired_state::{GroupEntry, LdapDesiredState, UserEntry};
use crate::live_state::LdapLiveState;
use nix_hapi_lib::dag::eval_jq_first;
use nix_hapi_lib::field_value::{FieldValueError, ResolvedFieldValue};
use nix_hapi_lib::plan::{FieldDiff, ResourceChange};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReconcileError {
  #[error("Failed to resolve field {field:?} for {entry:?}: {source}")]
  FieldResolution {
    entry: String,
    field: String,
    #[source]
    source: FieldValueError,
  },
}

/// A resolved user entry ready for comparison against live state.
struct ResolvedUser {
  attrs: HashMap<String, ResolvedFieldValue>,
}

/// A resolved group entry ready for comparison against live state.
struct ResolvedGroup {
  pub description: Option<ResolvedFieldValue>,
  pub members: Vec<String>,
}

/// The full set of changes the LDAP provider needs to make, separated by
/// operation type so the runbook generator can order them correctly.
pub struct LdapDiff {
  pub resource_changes: Vec<ResourceChange>,
  /// Entries to add: (dn, attrs-as-string-vecs).
  pub to_add: Vec<(String, HashMap<String, Vec<String>>)>,
  /// Entries to modify: (dn, attr-name → (old-values, new-values)).
  pub to_modify: Vec<(String, Vec<AttrMod>)>,
  /// DNs to delete, ordered deepest-first.
  pub to_delete: Vec<String>,
}

pub struct AttrMod {
  pub attr: String,
  pub op: AttrModOp,
  pub values: Vec<String>,
}

pub enum AttrModOp {
  Add,
  Replace,
}

/// Resolves and diffs `desired` against `live`, applying `ignore` expressions.
///
/// Each ignore expression is a jq filter evaluated with `.` bound to
/// `{"key": "<dn>", "resource_id": "<dn>"}`.  A truthy result exempts the
/// resource from deletion.
pub fn diff(
  desired: &LdapDesiredState,
  live: &LdapLiveState,
  base_dn: &str,
  ignore_exprs: &[String],
) -> Result<LdapDiff, ReconcileError> {
  let mut resource_changes = Vec::new();
  let mut to_add = Vec::new();
  let mut to_modify = Vec::new();
  let mut to_delete = Vec::new();

  // Reconcile users.
  for (uid, user) in &desired.users {
    let dn = user_dn(uid, base_dn);
    let resolved = resolve_user(uid, user)?;

    match live.users.get(uid) {
      None => {
        let attrs = resolved_to_attr_map(&resolved.attrs);
        let with_object_class = with_user_object_classes(attrs, uid);
        resource_changes.push(ResourceChange::Add {
          resource_id: dn.clone(),
          fields: with_user_object_classes(
            resolved_to_attr_map(&resolved.attrs),
            uid,
          )
          .into_iter()
          .map(|(k, v)| FieldDiff {
            field: k,
            from: None,
            to: Some(v.join("; ")),
          })
          .collect(),
        });
        to_add.push((dn, with_object_class));
      }
      Some(live_entry) => {
        let mods = diff_attrs(&resolved.attrs, live_entry);
        if !mods.is_empty() {
          let field_changes = mods
            .iter()
            .map(|m| FieldDiff {
              field: m.attr.clone(),
              from: live_entry.get(&m.attr).map(|v| v.join("; ")),
              to: Some(m.values.join("; ")),
            })
            .collect();
          resource_changes.push(ResourceChange::Modify {
            resource_id: dn.clone(),
            field_changes,
          });
          to_modify.push((dn, mods));
        }
      }
    }
  }

  // Warn about group members that reference users outside the desired set.
  let desired_user_keys: HashSet<&str> =
    desired.users.keys().map(|s| s.as_str()).collect();
  for (cn, group) in &desired.groups {
    for member in &group.members {
      if !desired_user_keys.contains(member.as_str()) {
        tracing::warn!(
          group = %cn,
          member = %member,
          "Group references member not present in desired users; \
           member may already exist from a previous run",
        );
      }
    }
  }

  // Reconcile groups.
  for (cn, group) in &desired.groups {
    let dn = group_dn(cn, base_dn);
    let resolved = resolve_group(cn, group)?;
    let desired_attrs = group_to_attr_map(&resolved, cn, base_dn);

    match live.groups.get(cn) {
      None => {
        resource_changes.push(ResourceChange::Add {
          resource_id: dn.clone(),
          fields: desired_attrs
            .iter()
            .map(|(k, v)| FieldDiff {
              field: k.clone(),
              from: None,
              to: Some(v.join("; ")),
            })
            .collect(),
        });
        to_add.push((dn, desired_attrs));
      }
      Some(live_entry) => {
        let mods = diff_multi_attrs(&desired_attrs, live_entry);
        if !mods.is_empty() {
          let field_changes = mods
            .iter()
            .map(|m| FieldDiff {
              field: m.attr.clone(),
              from: live_entry.get(&m.attr).map(|v| v.join("; ")),
              to: Some(m.values.join("; ")),
            })
            .collect();
          resource_changes.push(ResourceChange::Modify {
            resource_id: dn.clone(),
            field_changes,
          });
          to_modify.push((dn, mods));
        }
      }
    }
  }

  // Collect live users and groups not in desired state → candidates for deletion.
  let desired_uids: HashSet<&str> =
    desired.users.keys().map(|s| s.as_str()).collect();
  let desired_cns: HashSet<&str> =
    desired.groups.keys().map(|s| s.as_str()).collect();

  let mut delete_dns: Vec<String> = live
    .users
    .keys()
    .filter(|uid| !desired_uids.contains(uid.as_str()))
    .map(|uid| user_dn(uid, base_dn))
    .chain(
      live
        .groups
        .keys()
        .filter(|cn| !desired_cns.contains(cn.as_str()))
        .map(|cn| group_dn(cn, base_dn)),
    )
    .filter(|dn| !is_ignored(dn, ignore_exprs))
    .collect();

  // Delete deepest entries first so parents can be removed after children.
  delete_dns.sort_by_key(|dn| std::cmp::Reverse(dn_depth(dn)));

  for dn in &delete_dns {
    resource_changes.push(ResourceChange::Delete {
      resource_id: dn.clone(),
    });
  }
  to_delete.extend(delete_dns);

  // Additions must be ordered parents-before-children.
  to_add.sort_by_key(|(dn, _)| dn_depth(dn));

  Ok(LdapDiff {
    resource_changes,
    to_add,
    to_modify,
    to_delete,
  })
}

fn resolve_user(
  uid: &str,
  user: &UserEntry,
) -> Result<ResolvedUser, ReconcileError> {
  let mut attrs: HashMap<String, ResolvedFieldValue> = HashMap::new();

  macro_rules! resolve_field {
    ($field:expr, $value:expr) => {
      $value
        .resolve()
        .map_err(|source| ReconcileError::FieldResolution {
          entry: uid.to_string(),
          field: $field.to_string(),
          source,
        })?
    };
  }

  attrs.insert("cn".to_string(), resolve_field!("cn", user.cn));
  attrs.insert("sn".to_string(), resolve_field!("sn", user.sn));
  attrs.insert("mail".to_string(), resolve_field!("mail", user.mail));
  attrs.insert(
    "userPassword".to_string(),
    resolve_field!("userPassword", user.user_password),
  );

  if let Some(ref fv) = user.login_shell {
    attrs.insert("loginShell".to_string(), resolve_field!("loginShell", fv));
  }
  if let Some(ref fv) = user.description {
    attrs.insert("description".to_string(), resolve_field!("description", fv));
  }

  for (field, fv) in &user.extra_fields {
    attrs.insert(field.clone(), resolve_field!(field, fv));
  }

  Ok(ResolvedUser { attrs })
}

fn resolve_group(
  cn: &str,
  group: &GroupEntry,
) -> Result<ResolvedGroup, ReconcileError> {
  let description = group
    .description
    .as_ref()
    .map(|fv| {
      fv.resolve()
        .map_err(|source| ReconcileError::FieldResolution {
          entry: cn.to_string(),
          field: "description".to_string(),
          source,
        })
    })
    .transpose()?;

  Ok(ResolvedGroup {
    description,
    members: group.members.clone(),
  })
}

/// Lowers a JSON value to the LDAP attribute-value list representation.
///
/// LDAP attributes are inherently multi-valued (`Vec<String>` per attribute);
/// this helper bridges from the engine's `serde_json::Value` field-value
/// type to that representation, supporting:
///
///   * `Value::String("foo")`           → `vec!["foo"]`
///   * `Value::Array(["a","b","c"])`    → `vec!["a","b","c"]`  (multi-valued)
///   * `Value::Array([])`               → `vec![]`             (clear attribute)
///   * `Value::Number(42)`              → `vec!["42"]`         (stringified)
///   * `Value::Bool(true)`              → `vec!["true"]`       (stringified)
///   * `Value::Null`                    → `vec![]`             (clear attribute)
///
/// Non-scalar elements inside an array (nested arrays, objects, null) are
/// dropped with a warning rather than failing the whole reconciliation;
/// such values don't have a well-defined LDAP representation.  Top-level
/// objects are treated the same way.
fn value_to_attr_values(attr: &str, value: &serde_json::Value) -> Vec<String> {
  fn scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
      serde_json::Value::String(s) => Some(s.clone()),
      serde_json::Value::Number(n) => Some(n.to_string()),
      serde_json::Value::Bool(b) => Some(b.to_string()),
      _ => None,
    }
  }

  match value {
    serde_json::Value::Array(arr) => arr
      .iter()
      .filter_map(|v| {
        scalar_to_string(v).or_else(|| {
          tracing::warn!(
            attribute = attr,
            element = %v,
            "Skipping non-scalar element in multi-valued LDAP attribute",
          );
          None
        })
      })
      .collect(),
    serde_json::Value::Null => Vec::new(),
    serde_json::Value::Object(_) => {
      tracing::warn!(
        attribute = attr,
        "Skipping object-valued LDAP attribute; only strings, numbers, \
         booleans, and arrays of those are supported",
      );
      Vec::new()
    }
    other => scalar_to_string(other).map(|s| vec![s]).unwrap_or_default(),
  }
}

/// Computes attribute modifications needed to bring `live_entry` in line with
/// `resolved`.  Unmanaged fields are skipped.  Initial fields are skipped when
/// the attribute already exists in the live entry.
fn diff_attrs(
  resolved: &HashMap<String, ResolvedFieldValue>,
  live_entry: &HashMap<String, Vec<String>>,
) -> Vec<AttrMod> {
  let mut mods = Vec::new();

  for (attr, rfv) in resolved {
    match rfv {
      ResolvedFieldValue::Unmanaged => continue,
      ResolvedFieldValue::Initial(value) => {
        if live_entry.contains_key(attr) {
          continue;
        }
        let values = value_to_attr_values(attr, value);
        if values.is_empty() {
          continue;
        }
        mods.push(AttrMod {
          attr: attr.clone(),
          op: AttrModOp::Add,
          values,
        });
      }
      ResolvedFieldValue::Managed(value) => {
        let values = value_to_attr_values(attr, value);
        let live_vals = live_entry.get(attr);
        let desired_set: HashSet<&str> =
          values.iter().map(String::as_str).collect();
        let live_set: HashSet<&str> = live_vals
          .map(|v| v.iter().map(String::as_str).collect())
          .unwrap_or_default();

        if desired_set != live_set {
          let op = if live_vals.is_none() {
            AttrModOp::Add
          } else {
            AttrModOp::Replace
          };
          mods.push(AttrMod {
            attr: attr.clone(),
            op,
            values,
          });
        }
      }
      // DerivedFrom is always treated as a pending change: its final value
      // is not yet known, so we cannot compare against live state.
      ResolvedFieldValue::DerivedFrom { inputs } => {
        let op = if live_entry.contains_key(attr) {
          AttrModOp::Replace
        } else {
          AttrModOp::Add
        };
        mods.push(AttrMod {
          attr: attr.clone(),
          op,
          values: vec![format_derived_display(inputs)],
        });
      }
    }
  }

  mods
}

/// Compares desired multi-valued attributes against live, using set equality.
/// Used for group reconciliation where attributes like `member` and
/// `objectClass` are inherently multi-valued.
fn diff_multi_attrs(
  desired: &HashMap<String, Vec<String>>,
  live_entry: &HashMap<String, Vec<String>>,
) -> Vec<AttrMod> {
  desired
    .iter()
    .filter_map(|(attr, desired_vals)| {
      let desired_set: HashSet<&str> =
        desired_vals.iter().map(|s| s.as_str()).collect();
      let live_vals = live_entry.get(attr);
      let live_set: HashSet<&str> = live_vals
        .map(|v| v.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();

      (desired_set != live_set).then(|| {
        let op = if live_vals.is_none() {
          AttrModOp::Add
        } else {
          AttrModOp::Replace
        };
        AttrMod {
          attr: attr.clone(),
          op,
          values: desired_vals.clone(),
        }
      })
    })
    .collect()
}

fn resolved_to_attr_map(
  resolved: &HashMap<String, ResolvedFieldValue>,
) -> HashMap<String, Vec<String>> {
  resolved
    .iter()
    .filter_map(|(k, rfv)| match rfv {
      ResolvedFieldValue::Unmanaged => None,
      ResolvedFieldValue::DerivedFrom { inputs } => {
        Some((k.clone(), vec![format_derived_display(inputs)]))
      }
      _ => rfv.value().and_then(|v| {
        let values = value_to_attr_values(k, v);
        if values.is_empty() {
          None
        } else {
          Some((k.clone(), values))
        }
      }),
    })
    .collect()
}

/// Formats a `DerivedFrom` inputs map for display in plan output and LDIF
/// bodies.  Entries are sorted by alias for deterministic output.
fn format_derived_display(inputs: &HashMap<String, String>) -> String {
  let mut parts: Vec<String> = inputs
    .iter()
    .map(|(alias, path)| format!("{}={}", alias, path))
    .collect();
  parts.sort();
  format!("<derived from {}>", parts.join(", "))
}

fn with_user_object_classes(
  mut attrs: HashMap<String, Vec<String>>,
  uid: &str,
) -> HashMap<String, Vec<String>> {
  attrs.entry("objectClass".to_string()).or_insert_with(|| {
    vec![
      "inetOrgPerson".to_string(),
      "organizationalPerson".to_string(),
      "person".to_string(),
      "top".to_string(),
    ]
  });
  attrs
    .entry("uid".to_string())
    .or_insert_with(|| vec![uid.to_string()]);
  attrs
}

fn group_to_attr_map(
  group: &ResolvedGroup,
  cn: &str,
  base_dn: &str,
) -> HashMap<String, Vec<String>> {
  let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
  attrs.insert(
    "objectClass".to_string(),
    vec!["groupOfNames".to_string(), "top".to_string()],
  );
  attrs.insert("cn".to_string(), vec![cn.to_string()]);

  if let Some(desc) = group.description.as_ref().and_then(|rfv| rfv.as_str()) {
    attrs.insert("description".to_string(), vec![desc.to_string()]);
  }

  let member_dns: Vec<String> = if group.members.is_empty() {
    // groupOfNames requires at least one member; use a placeholder when empty.
    vec![format!("uid=placeholder,ou=users,{}", base_dn)]
  } else {
    group
      .members
      .iter()
      .map(|uid| user_dn(uid, base_dn))
      .collect()
  };
  attrs.insert("member".to_string(), member_dns);
  attrs
}

pub fn user_dn(uid: &str, base_dn: &str) -> String {
  format!("uid={},ou=users,{}", uid, base_dn)
}

pub fn group_dn(cn: &str, base_dn: &str) -> String {
  format!("cn={},ou=groups,{}", cn, base_dn)
}

pub fn ou_users_dn(base_dn: &str) -> String {
  format!("ou=users,{}", base_dn)
}

pub fn ou_groups_dn(base_dn: &str) -> String {
  format!("ou=groups,{}", base_dn)
}

fn dn_depth(dn: &str) -> usize {
  dn.split(',').count()
}

/// Evaluates ignore expressions against a resource DN.  Each expression
/// receives `.` as `{"key": "<dn>", "resource_id": "<dn>"}`.  If any
/// expression produces a truthy result, the resource is ignored.
fn is_ignored(dn: &str, exprs: &[String]) -> bool {
  exprs.iter().any(|expr| {
    let input = json!({"key": dn, "resource_id": dn});
    match eval_jq_first("(ignore)", expr, input) {
      Ok(result) => is_truthy(&result),
      Err(_) => false,
    }
  })
}

fn is_truthy(v: &serde_json::Value) -> bool {
  match v {
    serde_json::Value::Null => false,
    serde_json::Value::Bool(b) => *b,
    _ => true,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use nix_hapi_lib::field_value::FieldValue;

  #[test]
  fn value_to_attr_values_strings_become_singleton_vec() {
    assert_eq!(
      value_to_attr_values("cn", &serde_json::json!("Alice")),
      vec!["Alice".to_string()],
    );
  }

  #[test]
  fn value_to_attr_values_arrays_become_multi_value() {
    assert_eq!(
      value_to_attr_values(
        "objectClass",
        &serde_json::json!(["top", "person", "inetOrgPerson"]),
      ),
      vec![
        "top".to_string(),
        "person".to_string(),
        "inetOrgPerson".to_string(),
      ],
    );
  }

  #[test]
  fn value_to_attr_values_arrays_stringify_scalars() {
    assert_eq!(
      value_to_attr_values("uidNumber", &serde_json::json!([1001, true])),
      vec!["1001".to_string(), "true".to_string()],
    );
  }

  #[test]
  fn value_to_attr_values_arrays_skip_non_scalar_elements() {
    assert_eq!(
      value_to_attr_values(
        "objectClass",
        &serde_json::json!(["a", {"nested": "object"}, "b"]),
      ),
      vec!["a".to_string(), "b".to_string()],
    );
  }

  #[test]
  fn value_to_attr_values_empty_array_yields_empty_vec() {
    assert!(
      value_to_attr_values("memberOf", &serde_json::json!([])).is_empty(),
    );
  }

  #[test]
  fn value_to_attr_values_null_yields_empty_vec() {
    assert!(
      value_to_attr_values("description", &serde_json::Value::Null).is_empty(),
    );
  }

  #[test]
  fn value_to_attr_values_object_skipped_with_warning() {
    assert!(value_to_attr_values("weird", &serde_json::json!({"foo": "bar"}),)
      .is_empty());
  }

  fn empty_live() -> LdapLiveState {
    LdapLiveState::default()
  }

  fn make_user(cn: FieldValue, mail: FieldValue, pw: FieldValue) -> UserEntry {
    UserEntry {
      cn,
      sn: FieldValue::Managed {
        value: serde_json::Value::from("Test"),
      },
      mail,
      user_password: pw,
      login_shell: None,
      description: None,
      extra_fields: HashMap::new(),
    }
  }

  #[test]
  fn derived_from_field_appears_in_plan_diff_with_input_paths() {
    let inputs =
      [("uid".to_string(), r#".["hr"]["users"]["alice"]["id"]"#.to_string())]
        .into_iter()
        .collect::<HashMap<_, _>>();
    let user = make_user(
      FieldValue::DerivedFrom {
        inputs: inputs.clone(),
        expression: "mkManaged(.uid)".to_string(),
      },
      FieldValue::Managed {
        value: serde_json::Value::from("alice@example.com"),
      },
      FieldValue::Managed {
        value: serde_json::Value::from("secret"),
      },
    );

    let mut desired = LdapDesiredState::default();
    desired.users.insert("alice".to_string(), user);

    let result =
      diff(&desired, &empty_live(), "dc=example,dc=com", &[]).unwrap();

    assert_eq!(result.resource_changes.len(), 1);
    let change = &result.resource_changes[0];
    if let ResourceChange::Add { fields, .. } = change {
      let cn_diff = fields.iter().find(|f| f.field == "cn").unwrap();
      assert!(
        cn_diff
          .to
          .as_deref()
          .unwrap_or("")
          .contains("<derived from"),
        "expected derived-from display in 'to', got {:?}",
        cn_diff.to
      );
      assert!(
        cn_diff
          .to
          .as_deref()
          .unwrap_or("")
          .contains(r#".["hr"]["users"]["alice"]["id"]"#),
        "expected input path in display, got {:?}",
        cn_diff.to
      );
    } else {
      panic!("expected Add change, got {:?}", change);
    }
  }

  #[test]
  fn derived_from_field_always_shown_as_change_when_live_exists() {
    let inputs =
      [("uid".to_string(), r#".["hr"]["users"]["alice"]["id"]"#.to_string())]
        .into_iter()
        .collect::<HashMap<_, _>>();
    let user = make_user(
      FieldValue::DerivedFrom {
        inputs: inputs.clone(),
        expression: "mkManaged(.uid)".to_string(),
      },
      FieldValue::Managed {
        value: serde_json::Value::from("alice@example.com"),
      },
      FieldValue::Managed {
        value: serde_json::Value::from("secret"),
      },
    );

    let mut desired = LdapDesiredState::default();
    desired.users.insert("alice".to_string(), user);

    // Live state has alice with a cn value already set.
    let mut live = empty_live();
    live.users.insert(
      "alice".to_string(),
      [
        ("cn".to_string(), vec!["Alice Smith".to_string()]),
        ("mail".to_string(), vec!["alice@example.com".to_string()]),
        ("userPassword".to_string(), vec!["secret".to_string()]),
      ]
      .into_iter()
      .collect(),
    );

    let result = diff(&desired, &live, "dc=example,dc=com", &[]).unwrap();

    // DerivedFrom cn should always appear as a change even when live has a value.
    assert_eq!(result.resource_changes.len(), 1);
    if let ResourceChange::Modify { field_changes, .. } =
      &result.resource_changes[0]
    {
      let cn_change = field_changes.iter().find(|f| f.field == "cn").unwrap();
      assert!(
        cn_change
          .to
          .as_deref()
          .unwrap_or("")
          .contains("<derived from"),
        "expected derived-from display, got {:?}",
        cn_change.to
      );
    } else {
      panic!("expected Modify change");
    }
  }
}
