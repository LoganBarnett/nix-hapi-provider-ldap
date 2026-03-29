use crate::desired_state::{GroupEntry, LdapDesiredState, UserEntry};
use crate::live_state::LdapLiveState;
use nix_hapi_lib::field_value::{FieldValueError, ResolvedFieldValue};
use nix_hapi_lib::plan::{FieldDiff, ResourceChange};
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
  pub description: ResolvedFieldValue,
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

/// Resolves and diffs `desired` against `live`, applying `ignore` patterns.
pub fn diff(
  desired: &LdapDesiredState,
  live: &LdapLiveState,
  base_dn: &str,
  ignore_patterns: &[regex::Regex],
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
        let mock_resolved: HashMap<String, ResolvedFieldValue> = desired_attrs
          .iter()
          .map(|(k, v)| (k.clone(), ResolvedFieldValue::Managed(v.join("\n"))))
          .collect();
        let mods = diff_attrs(&mock_resolved, live_entry);
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
    .filter(|dn| !is_ignored(dn, ignore_patterns))
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
  let description = group.description.resolve().map_err(|source| {
    ReconcileError::FieldResolution {
      entry: cn.to_string(),
      field: "description".to_string(),
      source,
    }
  })?;

  Ok(ResolvedGroup {
    description,
    members: group.members.clone(),
  })
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
        mods.push(AttrMod {
          attr: attr.clone(),
          op: AttrModOp::Add,
          values: vec![value.clone()],
        });
      }
      ResolvedFieldValue::Managed(value) => {
        let live_vals = live_entry.get(attr);
        let desired_set: HashSet<&str> =
          std::iter::once(value.as_str()).collect();
        let live_set: HashSet<&str> = live_vals
          .map(|v| v.iter().map(|s| s.as_str()).collect())
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
            values: vec![value.clone()],
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
      _ => rfv.value().map(|v| (k.clone(), vec![v.to_string()])),
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
  attrs.insert("objectClass".to_string(), vec!["groupOfNames".to_string()]);
  attrs.insert("cn".to_string(), vec![cn.to_string()]);

  if let Some(desc) = group.description.value() {
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

fn is_ignored(dn: &str, patterns: &[regex::Regex]) -> bool {
  patterns.iter().any(|re| re.is_match(dn))
}

#[cfg(test)]
mod tests {
  use super::*;
  use nix_hapi_lib::field_value::FieldValue;

  fn empty_live() -> LdapLiveState {
    LdapLiveState::default()
  }

  fn make_user(cn: FieldValue, mail: FieldValue, pw: FieldValue) -> UserEntry {
    UserEntry {
      cn,
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
        value: "alice@example.com".to_string(),
      },
      FieldValue::Managed {
        value: "secret".to_string(),
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
        value: "alice@example.com".to_string(),
      },
      FieldValue::Managed {
        value: "secret".to_string(),
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
