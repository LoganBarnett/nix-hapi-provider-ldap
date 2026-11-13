use crate::search_base::{SearchBase, SearchBaseError};
use nix_hapi_lib::provider::{ProviderError, ResolvedConfig};
use serde_json::Value;
use thiserror::Error;

/// Resolved LDAP connection configuration and what the provider owns on the
/// server, extracted from a `ResolvedConfig`.
#[derive(Debug, Clone)]
pub struct ResolvedLdapConfig {
  pub url: String,
  pub bind_dn: String,
  pub bind_password: String,
  pub ownership: Ownership,
}

/// What the provider owns.  The Nix module always uses `NamingContexts`, so
/// the declaration is the record for the whole server; explicit bases exist
/// for callers that want less than that.
#[derive(Debug, Clone)]
pub enum Ownership {
  /// Exactly these RFC 4516 search bases.
  SearchBases(Vec<SearchBase>),
  /// Every naming context the server publishes in its root DSE, each owned
  /// in full, except those listed here (compared as normalised DNs).
  NamingContexts { unmanaged: Vec<String> },
}

/// Why a server's provider config could not be used.  The engine's
/// `ProviderError` is closed, so these flatten to `OperationFailed` at the
/// trait boundary with the message intact.
#[derive(Debug, Error)]
pub enum ConfigError {
  #[error(
    "Invalid LDAP URL {url:?}: must start with ldap://, ldaps://, or ldapi://"
  )]
  UrlScheme { url: String },

  #[error(
    "Config field {field:?} must be a Managed or Initial value; DerivedFrom \
     is not supported for provider config"
  )]
  Unresolved { field: String },

  #[error("Config field {field:?} must be a string, got {value}")]
  NotAString { field: String, value: Value },

  #[error("Config field {field:?} must be a list of strings, got {value}")]
  NotAStringList { field: String, value: Value },

  #[error(
    "Config field {field:?} must be a list of strings; element {index} is \
     {value}"
  )]
  StringListElement {
    field: String,
    index: usize,
    value: Value,
  },

  #[error(
    "Config must set \"unmanagedNamingContexts\" (own every naming context \
     the server publishes except those listed) or \"searchBases\" (own \
     exactly those RFC 4516 search bases)"
  )]
  OwnershipUnspecified,

  #[error(
    "Config sets both \"searchBases\" and \"unmanagedNamingContexts\"; set \
     exactly one"
  )]
  OwnershipAmbiguous,

  #[error(
    "Config field \"searchBases\" must list at least one LDAP URL; an empty \
     list would own no entries"
  )]
  SearchBasesEmpty,

  #[error(transparent)]
  SearchBase(#[from] SearchBaseError),
}

impl ResolvedLdapConfig {
  pub fn from_resolved_config(
    config: &ResolvedConfig,
  ) -> Result<Self, ProviderError> {
    Ok(ResolvedLdapConfig {
      url: ldap_url(config)?,
      bind_dn: require_string(config, "bindDn")?,
      bind_password: require_string(config, "bindPassword")?,
      ownership: ownership(config)?,
    })
  }
}

fn ldap_url(config: &ResolvedConfig) -> Result<String, ProviderError> {
  let url = require_string(config, "url")?;
  ["ldap://", "ldaps://", "ldapi://"]
    .iter()
    .any(|scheme| url.starts_with(scheme))
    .then_some(url.clone())
    .ok_or_else(|| config_err(ConfigError::UrlScheme { url }))
}

fn ownership(config: &ResolvedConfig) -> Result<Ownership, ProviderError> {
  match (
    config.contains_key("searchBases"),
    config.contains_key("unmanagedNamingContexts"),
  ) {
    (true, true) => Err(config_err(ConfigError::OwnershipAmbiguous)),
    (true, false) => search_bases(config).map(Ownership::SearchBases),
    (false, true) => require_string_list(config, "unmanagedNamingContexts")
      .map(|unmanaged| Ownership::NamingContexts { unmanaged }),
    (false, false) => Err(config_err(ConfigError::OwnershipUnspecified)),
  }
}

fn search_bases(
  config: &ResolvedConfig,
) -> Result<Vec<SearchBase>, ProviderError> {
  let urls = require_string_list(config, "searchBases")?;
  (!urls.is_empty())
    .then_some(())
    .ok_or(ConfigError::SearchBasesEmpty)
    .and_then(|_| {
      urls
        .iter()
        .map(|url| SearchBase::parse(url).map_err(ConfigError::from))
        .collect()
    })
    .map_err(config_err)
}

/// The concrete value of a required config field.  Missing and unmanaged
/// fields map to the engine's own variants; a `DerivedFrom` field has no
/// value to give.
fn require_value<'a>(
  config: &'a ResolvedConfig,
  field: &str,
) -> Result<&'a Value, ProviderError> {
  match config.get(field) {
    None => Err(ProviderError::MissingConfig {
      field: field.to_string(),
    }),
    Some(rfv) if rfv.is_unmanaged() => Err(ProviderError::UnmanagedConfig {
      field: field.to_string(),
    }),
    Some(rfv) => rfv.value().ok_or_else(|| {
      config_err(ConfigError::Unresolved {
        field: field.to_string(),
      })
    }),
  }
}

fn require_string(
  config: &ResolvedConfig,
  field: &str,
) -> Result<String, ProviderError> {
  let value = require_value(config, field)?;
  value.as_str().map(String::from).ok_or_else(|| {
    config_err(ConfigError::NotAString {
      field: field.to_string(),
      value: value.clone(),
    })
  })
}

fn require_string_list(
  config: &ResolvedConfig,
  field: &str,
) -> Result<Vec<String>, ProviderError> {
  let value = require_value(config, field)?;
  value
    .as_array()
    .ok_or_else(|| ConfigError::NotAStringList {
      field: field.to_string(),
      value: value.clone(),
    })
    .and_then(|items| {
      items
        .iter()
        .enumerate()
        .map(|(index, item)| {
          item.as_str().map(String::from).ok_or_else(|| {
            ConfigError::StringListElement {
              field: field.to_string(),
              index,
              value: item.clone(),
            }
          })
        })
        .collect()
    })
    .map_err(config_err)
}

fn config_err(e: ConfigError) -> ProviderError {
  ProviderError::OperationFailed(e.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;
  use nix_hapi_lib::field_value::ResolvedFieldValue;
  use serde_json::json;
  use std::collections::HashMap;

  fn connection() -> ResolvedConfig {
    HashMap::from([
      ("url".to_string(), managed(json!("ldap://localhost:389"))),
      ("bindDn".to_string(), managed(json!("cn=admin,dc=test,dc=local"))),
      ("bindPassword".to_string(), managed(json!("secret"))),
    ])
  }

  /// A complete config with explicit bases; tests override one field each.
  fn base_config() -> ResolvedConfig {
    with(
      connection(),
      "searchBases",
      managed(json!(["ldap:///ou=users,dc=test,dc=local??one"])),
    )
  }

  fn with(
    mut config: ResolvedConfig,
    field: &str,
    value: ResolvedFieldValue,
  ) -> ResolvedConfig {
    config.insert(field.to_string(), value);
    config
  }

  fn managed(value: Value) -> ResolvedFieldValue {
    ResolvedFieldValue::Managed(value)
  }

  fn error_of(config: ResolvedConfig) -> String {
    ResolvedLdapConfig::from_resolved_config(&config)
      .expect_err("expected an error")
      .to_string()
  }

  fn error_with(field: &str, value: ResolvedFieldValue) -> String {
    error_of(with(base_config(), field, value))
  }

  #[test]
  fn complete_config_parses_its_search_bases() {
    let config = ResolvedLdapConfig::from_resolved_config(&base_config())
      .expect("valid config");
    match config.ownership {
      Ownership::SearchBases(bases) => {
        assert_eq!(bases.len(), 1);
        assert_eq!(bases[0].base, "ou=users,dc=test,dc=local");
      }
      other => panic!("expected explicit bases, got {other:?}"),
    }
  }

  #[test]
  fn naming_contexts_ownership_parses() {
    let config = ResolvedLdapConfig::from_resolved_config(&with(
      connection(),
      "unmanagedNamingContexts",
      managed(json!(["cn=config", "cn=monitor"])),
    ))
    .expect("valid config");
    match config.ownership {
      Ownership::NamingContexts { unmanaged } => {
        assert_eq!(unmanaged, vec!["cn=config", "cn=monitor"]);
      }
      other => panic!("expected naming contexts, got {other:?}"),
    }
  }

  #[test]
  fn base_dn_is_not_required() {
    assert!(!base_config().contains_key("baseDn"));
    assert!(ResolvedLdapConfig::from_resolved_config(&base_config()).is_ok());
  }

  #[test]
  fn ownership_must_be_specified() {
    let msg = error_of(connection());
    assert!(msg.contains("unmanagedNamingContexts"), "{msg}");
    assert!(msg.contains("searchBases"), "{msg}");
  }

  #[test]
  fn ownership_must_not_be_ambiguous() {
    let msg = error_with("unmanagedNamingContexts", managed(json!([])));
    assert!(msg.contains("exactly one"), "{msg}");
  }

  #[test]
  fn invalid_url_scheme_returns_error() {
    let msg = error_with("url", managed(json!("garbage")));
    assert!(msg.contains("Invalid LDAP URL"), "{msg}");
  }

  #[test]
  fn derived_from_config_field_returns_error_not_panic() {
    let derived = ResolvedFieldValue::DerivedFrom {
      inputs: [("x".to_string(), ".some.path".to_string())]
        .into_iter()
        .collect(),
    };
    let msg = error_with("url", derived);
    assert!(msg.contains("DerivedFrom"), "{msg}");
  }

  #[test]
  fn malformed_search_base_names_the_url() {
    let url = "ldap:///ou=users,dc=test,dc=local??bogus";
    let msg = error_with("searchBases", managed(json!([url])));
    assert!(msg.contains(url), "{msg}");
  }

  #[test]
  fn empty_search_bases_is_rejected() {
    let msg = error_with("searchBases", managed(json!([])));
    assert!(msg.contains("at least one"), "{msg}");
  }

  #[test]
  fn non_string_search_base_names_the_element() {
    let msg =
      error_with("searchBases", managed(json!(["ldap:///dc=t??one", 7])));
    assert!(msg.contains("element 1"), "{msg}");
  }
}
