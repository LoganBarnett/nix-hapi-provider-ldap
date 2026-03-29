use crate::config::ResolvedLdapConfig;
use ldap3::{LdapConn, LdapError};
use nix_hapi_lib::provider::ProviderError;

/// Opens and authenticates an LDAP connection from resolved configuration.
pub fn connect(config: &ResolvedLdapConfig) -> Result<LdapConn, ProviderError> {
  let mut ldap = LdapConn::new(&config.url).map_err(|e| {
    ProviderError::ConnectionFailed(format!(
      "Failed to connect to {} (is the server reachable?): {}",
      config.url, e
    ))
  })?;

  ldap
    .simple_bind(&config.bind_dn, &config.bind_password)
    .map_err(|e| {
      ProviderError::ConnectionFailed(format!(
        "Failed to bind as {} to {}: {}",
        config.bind_dn, config.url, e
      ))
    })?
    .success()
    .map_err(|e| {
      let detail = bind_error_detail(&e);
      ProviderError::ConnectionFailed(format!(
        "Bind rejected for {} at {}{}: {}",
        config.bind_dn, config.url, detail, e
      ))
    })?;

  Ok(ldap)
}

/// Extracts a human-friendly hint from common LDAP bind error codes.
fn bind_error_detail(err: &LdapError) -> String {
  if let LdapError::LdapResult { result } = err {
    match result.rc {
      49 => " (invalid credentials)".to_string(),
      32 => " (bind DN not found)".to_string(),
      _ => String::new(),
    }
  } else {
    String::new()
  }
}
