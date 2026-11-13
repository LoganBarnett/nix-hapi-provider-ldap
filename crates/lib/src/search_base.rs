//! Search bases: the regions of the directory the provider owns.
//!
//! Each base is an RFC 4516 LDAP URL, `ldap:///<base>?<attrs>?<scope>?<filter>`,
//! because that is LDAP's own spelling for exactly (base, scope, filter) and
//! `ldapsearch -H` accepts it verbatim.  The provider owns every entry a
//! base's search returns, and anything owned but undeclared is deleted, so
//! the grammar is deliberately strict: the scope must be explicit, the
//! attribute list must be empty, and extensions are refused.

use crate::dn::{is_child_of, is_descendant_of, same_dn};
use percent_encoding::percent_decode_str;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SearchBaseError {
  #[error(
    "Search base URL {url:?} must start with \"ldap:///\" (an RFC 4516 URL \
     with an empty host; the server comes from the \"url\" config field)"
  )]
  Scheme { url: String },

  #[error(
    "Search base URL {url:?} names no base DN; expected \
     \"ldap:///<base dn>??<base|one|sub>?<filter>\""
  )]
  EmptyBase { url: String },

  #[error(
    "Search base URL {url:?} requests attributes {attributes:?}; the \
     attribute list must be empty because the provider always fetches every \
     attribute"
  )]
  Attributes { url: String, attributes: String },

  #[error(
    "Search base URL {url:?} has scope {scope:?}; expected an explicit \
     \"base\", \"one\" or \"sub\""
  )]
  Scope { url: String, scope: String },

  #[error(
    "Search base URL {url:?} carries extensions {extensions:?}, which are not \
     supported; a \"?\" inside the filter must be percent-encoded as %3F"
  )]
  Extensions { url: String, extensions: String },

  #[error(
    "Search base URL {url:?} has a {component} that is not valid \
     percent-encoded UTF-8: {source}"
  )]
  PercentDecoding {
    url: String,
    component: &'static str,
    #[source]
    source: std::str::Utf8Error,
  },

  #[error(
    "Search base URL {url:?} has a filter {filter:?} that is not a valid RFC \
     4515 search filter"
  )]
  Filter { url: String, filter: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
  Base,
  One,
  Sub,
}

impl SearchScope {
  pub fn ldap_scope(self) -> ldap3::Scope {
    match self {
      SearchScope::Base => ldap3::Scope::Base,
      SearchScope::One => ldap3::Scope::OneLevel,
      SearchScope::Sub => ldap3::Scope::Subtree,
    }
  }

  fn parse(scope: &str) -> Option<Self> {
    match scope {
      "base" => Some(SearchScope::Base),
      "one" => Some(SearchScope::One),
      "sub" => Some(SearchScope::Sub),
      _ => None,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchBase {
  /// The URL exactly as configured, so errors and plans can name it verbatim.
  pub url: String,
  pub base: String,
  pub scope: SearchScope,
  pub filter: String,
}

const PREFIX: &str = "ldap:///";
const DEFAULT_FILTER: &str = "(objectClass=*)";

impl SearchBase {
  pub fn parse(url: &str) -> Result<Self, SearchBaseError> {
    let segments: Vec<&str> = strip_scheme(url)?.split('?').collect();
    let component = |index: usize| segments.get(index).copied().unwrap_or("");
    let base = decode(url, "base DN", component(0))?;
    ensure(!base.trim().is_empty(), || SearchBaseError::EmptyBase {
      url: url.to_string(),
    })?;
    ensure(component(1).is_empty(), || SearchBaseError::Attributes {
      url: url.to_string(),
      attributes: component(1).to_string(),
    })?;
    let scope = SearchScope::parse(component(2)).ok_or_else(|| {
      SearchBaseError::Scope {
        url: url.to_string(),
        scope: component(2).to_string(),
      }
    })?;
    let filter = match component(3) {
      "" => DEFAULT_FILTER.to_string(),
      raw => decode(url, "filter", raw)?,
    };
    let extensions = segments.get(4..).map(|rest| rest.join("?"));
    ensure(extensions.as_deref().unwrap_or("").is_empty(), || {
      SearchBaseError::Extensions {
        url: url.to_string(),
        extensions: extensions.clone().unwrap_or_default(),
      }
    })?;
    ensure(ldap3::parse_filter(&filter).is_ok(), || SearchBaseError::Filter {
      url: url.to_string(),
      filter: filter.clone(),
    })?;
    Ok(SearchBase {
      url: url.to_string(),
      base,
      scope,
      filter,
    })
  }

  /// A base owning a whole tree: the entry at `dn` and everything beneath
  /// it.  This is how a naming context the server publishes is owned.
  pub fn subtree(dn: &str) -> Self {
    SearchBase {
      url: format!("{PREFIX}{dn}??sub"),
      base: dn.to_string(),
      scope: SearchScope::Sub,
      filter: DEFAULT_FILTER.to_string(),
    }
  }

  /// True when an entry at `dn` belongs to this base, with LDAP's own
  /// meaning of each scope: `sub` includes the base entry itself.  The same
  /// predicate filters search results and validates planned operations, so
  /// the two notions of ownership cannot drift apart.
  pub fn covers(&self, dn: &str) -> bool {
    match self.scope {
      SearchScope::Base => same_dn(dn, &self.base),
      SearchScope::One => is_child_of(dn, &self.base),
      SearchScope::Sub => {
        same_dn(dn, &self.base) || is_descendant_of(dn, &self.base)
      }
    }
  }
}

fn strip_scheme(url: &str) -> Result<&str, SearchBaseError> {
  url
    .get(..PREFIX.len())
    .filter(|head| head.eq_ignore_ascii_case(PREFIX))
    .map(|_| &url[PREFIX.len()..])
    .ok_or_else(|| SearchBaseError::Scheme {
      url: url.to_string(),
    })
}

fn decode(
  url: &str,
  component: &'static str,
  raw: &str,
) -> Result<String, SearchBaseError> {
  percent_decode_str(raw)
    .decode_utf8()
    .map(|decoded| decoded.into_owned())
    .map_err(|source| SearchBaseError::PercentDecoding {
      url: url.to_string(),
      component,
      source,
    })
}

fn ensure<E>(ok: bool, err: impl FnOnce() -> E) -> Result<(), E> {
  ok.then_some(()).ok_or_else(err)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn parsed(url: &str) -> SearchBase {
    SearchBase::parse(url).unwrap_or_else(|e| panic!("{url}: {e}"))
  }

  fn error_for(url: &str) -> String {
    SearchBase::parse(url)
      .err()
      .unwrap_or_else(|| panic!("{url} should not parse"))
      .to_string()
  }

  #[test]
  fn one_level_with_default_filter() {
    let base = parsed("ldap:///ou=users,dc=test,dc=local??one");
    assert_eq!(base.base, "ou=users,dc=test,dc=local");
    assert_eq!(base.scope, SearchScope::One);
    assert_eq!(base.filter, DEFAULT_FILTER);
  }

  #[test]
  fn subtree_with_filter_and_percent_encoding() {
    let base = parsed(
      "LDAP:///ou=Service%20Accounts,dc=test??sub?(%7C(objectClass=a)(objectClass=b))",
    );
    assert_eq!(base.base, "ou=Service Accounts,dc=test");
    assert_eq!(base.scope, SearchScope::Sub);
    assert_eq!(base.filter, "(|(objectClass=a)(objectClass=b))");
  }

  #[test]
  fn raw_space_in_base_is_accepted() {
    assert_eq!(
      parsed("ldap:///ou=Service Accounts,dc=test??base").base,
      "ou=Service Accounts,dc=test",
    );
  }

  #[test]
  fn every_error_names_the_url() {
    for url in [
      "ldaps:///ou=users,dc=test??one",
      "ldap://host/ou=users,dc=test??one",
      "ldap:///??one",
      "ldap:///ou=users,dc=test?cn?one",
      "ldap:///ou=users,dc=test",
      "ldap:///ou=users,dc=test??",
      "ldap:///ou=users,dc=test??bogus",
      "ldap:///ou=users,dc=test??one?(objectClass=*)?x-ext",
      "ldap:///ou=users,dc=test??one?(objectClass=*)?a?b",
      "ldap:///ou=users,dc=test??one?%FF",
      "ldap:///ou=users,dc=test??one?(unbalanced",
    ] {
      assert!(error_for(url).contains(url), "{url}");
    }
  }

  #[test]
  fn error_variants_are_distinguished() {
    assert!(error_for("ldaps:///ou=u,dc=t??one").contains("ldap:///"));
    assert!(error_for("ldap:///??one").contains("no base DN"));
    assert!(error_for("ldap:///ou=u,dc=t?cn?one").contains("attributes"));
    assert!(error_for("ldap:///ou=u,dc=t").contains("scope \"\""));
    assert!(error_for("ldap:///ou=u,dc=t??bogus").contains("scope \"bogus\""));
    assert!(error_for("ldap:///ou=u,dc=t??one??x").contains("extensions"));
    assert!(error_for("ldap:///ou=u,dc=t??one?%FF").contains("percent-encoded"));
    assert!(error_for("ldap:///ou=u,dc=t??one?(x").contains("RFC 4515"));
  }

  #[test]
  fn covers_follows_the_scope() {
    let users = "ou=users,dc=test,dc=local";
    let base = parsed(&format!("ldap:///{users}??base"));
    let one = parsed(&format!("ldap:///{users}??one"));
    let sub = parsed(&format!("ldap:///{users}??sub"));
    let child = "uid=alice,OU=Users,dc=test,dc=local";
    let grandchild = "uid=deep,ou=admins,ou=users,dc=test,dc=local";

    assert!(base.covers("OU=users, dc=test,dc=local"));
    assert!(!base.covers(child));

    assert!(one.covers(child));
    assert!(!one.covers(grandchild));
    assert!(!one.covers(users));

    assert!(sub.covers(child));
    assert!(sub.covers(grandchild));
    assert!(sub.covers(users));
    assert!(!sub.covers("dc=test,dc=local"));

    let context = SearchBase::subtree(users);
    assert!(context.covers(users));
    assert!(context.covers(grandchild));
    assert_eq!(context.url, format!("ldap:///{users}??sub"));
  }
}
