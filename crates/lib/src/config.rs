use nix_hapi_lib::provider::{ProviderError, ResolvedConfig};

/// Resolved LDAP connection configuration extracted from a `ResolvedConfig`.
#[derive(Debug, Clone)]
pub struct ResolvedLdapConfig {
  pub url: String,
  pub base_dn: String,
  pub bind_dn: String,
  pub bind_password: String,
}

impl ResolvedLdapConfig {
  pub fn from_resolved_config(
    config: &ResolvedConfig,
  ) -> Result<Self, ProviderError> {
    let url = require_string(config, "url")?;
    if !url.starts_with("ldap://")
      && !url.starts_with("ldaps://")
      && !url.starts_with("ldapi://")
    {
      return Err(ProviderError::OperationFailed(format!(
        "Invalid LDAP URL {:?}: must start with ldap://, ldaps://, or ldapi://",
        url,
      )));
    }
    Ok(ResolvedLdapConfig {
      url,
      base_dn: require_string(config, "baseDn")?,
      bind_dn: require_string(config, "bindDn")?,
      bind_password: require_string(config, "bindPassword")?,
    })
  }
}

/// Extracts a required concrete string value from a `ResolvedConfig` entry.
/// Returns an error if the field is missing, unmanaged, or DerivedFrom.
fn require_string(
  config: &ResolvedConfig,
  field: &str,
) -> Result<String, ProviderError> {
  match config.get(field) {
    None => Err(ProviderError::MissingConfig {
      field: field.to_string(),
    }),
    Some(rfv) if rfv.is_unmanaged() => Err(ProviderError::UnmanagedConfig {
      field: field.to_string(),
    }),
    Some(rfv) => rfv
      .value()
      .map(|v| v.to_string())
      .ok_or_else(|| ProviderError::OperationFailed(format!(
        "Config field {:?} cannot be DerivedFrom; provider configuration requires a concrete value",
        field,
      ))),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use nix_hapi_lib::field_value::ResolvedFieldValue;
  use std::collections::HashMap;

  #[test]
  fn invalid_url_scheme_returns_error() {
    let mut config: ResolvedConfig = HashMap::new();
    config.insert(
      "url".to_string(),
      ResolvedFieldValue::Managed("garbage".to_string()),
    );
    config.insert(
      "baseDn".to_string(),
      ResolvedFieldValue::Managed("dc=test,dc=local".to_string()),
    );
    config.insert(
      "bindDn".to_string(),
      ResolvedFieldValue::Managed("cn=admin,dc=test,dc=local".to_string()),
    );
    config.insert(
      "bindPassword".to_string(),
      ResolvedFieldValue::Managed("secret".to_string()),
    );

    let result = ResolvedLdapConfig::from_resolved_config(&config);
    assert!(result.is_err(), "Expected error for invalid URL scheme");
    let msg = result.unwrap_err().to_string();
    assert!(
      msg.contains("Invalid LDAP URL"),
      "Error should mention invalid URL: {}",
      msg,
    );
  }

  #[test]
  fn derived_from_config_field_returns_error_not_panic() {
    let mut config: ResolvedConfig = HashMap::new();
    config.insert(
      "url".to_string(),
      ResolvedFieldValue::DerivedFrom {
        inputs: [("x".to_string(), ".some.path".to_string())]
          .into_iter()
          .collect(),
      },
    );
    config.insert(
      "baseDn".to_string(),
      ResolvedFieldValue::Managed("dc=test,dc=local".to_string()),
    );
    config.insert(
      "bindDn".to_string(),
      ResolvedFieldValue::Managed("cn=admin,dc=test,dc=local".to_string()),
    );
    config.insert(
      "bindPassword".to_string(),
      ResolvedFieldValue::Managed("secret".to_string()),
    );

    let result = ResolvedLdapConfig::from_resolved_config(&config);
    assert!(result.is_err(), "Expected error for DerivedFrom config field");
    let msg = result.unwrap_err().to_string();
    assert!(
      msg.contains("DerivedFrom"),
      "Error should mention DerivedFrom: {}",
      msg
    );
  }
}
