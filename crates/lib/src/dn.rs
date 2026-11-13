//! String-level helpers for LDAP distinguished names.
//!
//! A DN is treated as a comma-separated list of `attribute=value` components
//! and escapes are never interpreted, so escaped commas (`cn=Smith\, J`),
//! multi-valued RDNs (`cn=a+sn=b`) and hex escapes are unsupported.  The
//! engine's providerKey matching is string-exact regardless; the normalised
//! comparison here only decides search base coverage.

/// Splits a DN into its leftmost RDN and the parent DN.  `None` for a DN with
/// no comma, which the provider never produces but is defensible.
pub(crate) fn split_rdn_parent(dn: &str) -> Option<(&str, &str)> {
  dn.split_once(',')
}

/// The parent DN, e.g. `ou=users,dc=example,dc=org` for a user entry.
pub(crate) fn parent_of(dn: &str) -> Option<&str> {
  split_rdn_parent(dn).map(|(_, parent)| parent)
}

/// The RDN of `dn` as (attribute, value), e.g. `("uid", "alice")`, with
/// surrounding whitespace trimmed from both halves.
pub(crate) fn rdn_of(dn: &str) -> Option<(&str, &str)> {
  dn.split(',')
    .next()
    .and_then(|rdn| rdn.split_once('='))
    .map(|(attr, value)| (attr.trim(), value.trim()))
}

pub(crate) fn dn_depth(dn: &str) -> usize {
  dn.split(',').count()
}

/// `dn` in a form fit for equality tests: lowercased, with whitespace around
/// `,` and `=` dropped.  LDAP matches the attribute types this provider meets
/// case-insensitively, so spellings that differ only this way name the same
/// entry.  Never used for anything sent to the server, because lowercasing an
/// RDN would change the stored naming value.
pub(crate) fn normalise_dn(dn: &str) -> String {
  dn.split(',')
    .map(|component| match component.split_once('=') {
      Some((attr, value)) => format!("{}={}", attr.trim(), value.trim()),
      None => component.trim().to_string(),
    })
    .collect::<Vec<_>>()
    .join(",")
    .to_lowercase()
}

pub(crate) fn same_dn(a: &str, b: &str) -> bool {
  normalise_dn(a) == normalise_dn(b)
}

/// True when `dn` is a direct child of `parent`.
pub(crate) fn is_child_of(dn: &str, parent: &str) -> bool {
  parent_of(dn).is_some_and(|p| same_dn(p, parent))
}

/// True when `dn` is a strict descendant of `ancestor`.  Anchoring on the
/// separating comma keeps `ou=xusers` from matching `ou=users` and keeps an
/// entry from being its own descendant.
pub(crate) fn is_descendant_of(dn: &str, ancestor: &str) -> bool {
  normalise_dn(dn).ends_with(&format!(",{}", normalise_dn(ancestor)))
}

#[cfg(test)]
mod tests {
  use super::*;

  const USERS: &str = "ou=users,dc=test,dc=local";

  #[test]
  fn normalise_lowercases_and_strips_separator_whitespace() {
    assert_eq!(
      normalise_dn("UID=Alice, ou = Users ,dc=test,dc=local"),
      "uid=alice,ou=users,dc=test,dc=local",
    );
  }

  #[test]
  fn rdn_of_trims_both_halves() {
    assert_eq!(rdn_of(" uid = alice ,ou=users"), Some(("uid", "alice")));
    assert_eq!(rdn_of("dc=local"), Some(("dc", "local")));
    assert_eq!(rdn_of("nonsense"), None);
  }

  #[test]
  fn child_requires_the_immediate_parent() {
    assert!(is_child_of("uid=alice,ou=users,dc=test,dc=local", USERS));
    assert!(is_child_of("uid=alice,OU=Users, dc=test,dc=local", USERS));
    assert!(!is_child_of(
      "uid=deep,ou=admins,ou=users,dc=test,dc=local",
      USERS
    ));
    assert!(!is_child_of(USERS, USERS));
    assert!(!is_child_of("uid=alice,ou=groups,dc=test,dc=local", USERS));
  }

  #[test]
  fn descendant_is_strict_and_anchored_on_the_comma() {
    assert!(is_descendant_of("uid=alice,ou=users,dc=test,dc=local", USERS));
    assert!(is_descendant_of(
      "uid=deep,ou=admins,ou=users,dc=test,dc=local",
      USERS
    ));
    assert!(!is_descendant_of(USERS, USERS));
    assert!(!is_descendant_of("uid=alice,ou=xusers,dc=test,dc=local", USERS));
    assert!(!is_descendant_of("uid=alice,ou=groups,dc=test,dc=local", USERS));
  }
}
