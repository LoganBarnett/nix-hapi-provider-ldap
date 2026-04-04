use crate::config::ResolvedLdapConfig;
use ldap3::{Ldap, LdapConnAsync, LdapError};
use nix_hapi_lib::provider::ProviderError;

/// Opens and authenticates an async LDAP connection from resolved
/// configuration.  Spawns a background task to drive the connection.
pub async fn connect(
  config: &ResolvedLdapConfig,
) -> Result<Ldap, ProviderError> {
  let (conn, mut ldap) =
    LdapConnAsync::new(&config.url).await.map_err(|e| {
      ProviderError::ConnectionFailed(format!(
        "Failed to connect to {} (is the server reachable?): {}",
        config.url, e
      ))
    })?;
  // The connection driver must run in a background task.
  tokio::spawn(async move {
    let _ = conn.drive().await;
  });

  ldap
    .simple_bind(&config.bind_dn, &config.bind_password)
    .await
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
