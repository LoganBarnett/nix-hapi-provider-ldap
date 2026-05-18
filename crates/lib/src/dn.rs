//! Helpers for composing and decomposing LDAP DNs used by the provider.
//!
//! The provider's `__nixhapi.providerKey` head is the entry's full DN as a
//! JSON string; these functions establish the conventions for how user and
//! group DNs are formed from a base DN, and how the leftmost RDN can be
//! taken back apart when emitting live state.

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

/// Extracts the value of a named RDN component from a DN string.
/// e.g. `rdn_value("uid=alice,ou=users,dc=example,dc=org", "uid")`
/// returns `Some("alice")`.
pub fn rdn_value(dn: &str, attr: &str) -> Option<String> {
  dn.split(',').next().and_then(|rdn| {
    let (k, v) = rdn.split_once('=')?;
    (k.trim().eq_ignore_ascii_case(attr)).then(|| v.trim().to_string())
  })
}
