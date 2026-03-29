use crate::config::ResolvedLdapConfig;
use ldap3::LdapConn;
use nix_hapi_lib::provider::ProviderError;

/// Opens and authenticates an LDAP connection from resolved configuration.
pub fn connect(config: &ResolvedLdapConfig) -> Result<LdapConn, ProviderError> {
  let mut ldap = LdapConn::new(&config.url).map_err(|e| {
    ProviderError::ConnectionFailed(format!(
      "Failed to connect to {}: {}",
      config.url, e
    ))
  })?;

  ldap
    .simple_bind(&config.bind_dn, &config.bind_password)
    .map_err(|e| {
      ProviderError::ConnectionFailed(format!(
        "Failed to bind as {}: {}",
        config.bind_dn, e
      ))
    })?
    .success()
    .map_err(|e| {
      ProviderError::ConnectionFailed(format!(
        "Bind rejected for {}: {}",
        config.bind_dn, e
      ))
    })?;

  Ok(ldap)
}
