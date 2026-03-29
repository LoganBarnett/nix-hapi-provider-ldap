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
    Ok(ResolvedLdapConfig {
      url: require_string(config, "url")?,
      base_dn: require_string(config, "baseDn")?,
      bind_dn: require_string(config, "bindDn")?,
      bind_password: require_string(config, "bindPassword")?,
    })
  }
}

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
    Some(rfv) => Ok(rfv.value().unwrap().to_string()),
  }
}
