use nix_hapi_lib::field_value::FieldValue;
use serde::Deserialize;
use std::collections::HashMap;

/// The LDAP provider's desired state, as parsed from the provider subtree.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LdapDesiredState {
  #[serde(default)]
  pub users: HashMap<String, UserEntry>,

  #[serde(default)]
  pub groups: HashMap<String, GroupEntry>,
}

/// A desired LDAP user entry.  Fields not listed here can be expressed via
/// `extra_fields`.  Missing required fields are reported as validation errors
/// at plan time.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEntry {
  pub cn: FieldValue,
  pub mail: FieldValue,
  pub user_password: FieldValue,

  #[serde(default)]
  pub login_shell: Option<FieldValue>,

  #[serde(default)]
  pub description: Option<FieldValue>,

  /// Any additional LDAP attributes not captured by the named fields above.
  #[serde(flatten)]
  pub extra_fields: HashMap<String, FieldValue>,
}

/// A desired LDAP group entry.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupEntry {
  pub description: FieldValue,

  /// Usernames (uid values) of group members.  The provider constructs
  /// the full member DNs from these values and the configured `base_dn`.
  #[serde(default)]
  pub members: Vec<String>,
}
