use ldap3::{Ldap, LdapError, Mod, SearchEntry};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum OperationError {
  #[error("Failed to add entry '{dn}': {source}")]
  AddFailed {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to modify entry '{dn}': {source}")]
  ModifyFailed {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to delete entry '{dn}': {source}")]
  DeleteFailed {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to search under '{base}': {source}")]
  SearchFailed {
    base: String,
    #[source]
    source: LdapError,
  },
}

/// Adds an entry.  If the entry already exists (rc=68), falls back to a
/// Modify that replaces each attribute so the entry ends up with the desired
/// values rather than silently keeping stale ones.
pub async fn entry_add(
  ldap: &mut Ldap,
  dn: &str,
  attrs: Vec<(&str, HashSet<&str>)>,
) -> Result<(), OperationError> {
  let add_result = ldap.add(dn, attrs.clone()).await;
  match add_result {
    Ok(result) => match result.success() {
      Ok(_) => Ok(()),
      Err(LdapError::LdapResult { result: ref r }) if r.rc == 68 => {
        warn!(dn = %dn, "Entry already exists (rc=68); falling back to modify");
        let mods: Vec<Mod<&str>> = attrs
          .into_iter()
          .map(|(attr, values)| Mod::Replace(attr, values))
          .collect();
        entry_modify(ldap, dn, mods).await
      }
      Err(e) => Err(OperationError::AddFailed {
        dn: dn.to_string(),
        source: e,
      }),
    },
    Err(e) => Err(OperationError::AddFailed {
      dn: dn.to_string(),
      source: e,
    }),
  }
}

/// Modifies an entry's attributes.
pub async fn entry_modify(
  ldap: &mut Ldap,
  dn: &str,
  mods: Vec<Mod<&str>>,
) -> Result<(), OperationError> {
  ldap
    .modify(dn, mods)
    .await
    .map_err(|source| OperationError::ModifyFailed {
      dn: dn.to_string(),
      source,
    })?
    .success()
    .map(|_| ())
    .map_err(|source| OperationError::ModifyFailed {
      dn: dn.to_string(),
      source,
    })
}

/// Deletes an entry.  Treats "no such object" (rc=32) as success for
/// idempotency.
pub async fn entry_delete(
  ldap: &mut Ldap,
  dn: &str,
) -> Result<(), OperationError> {
  match ldap.delete(dn).await {
    Ok(result) => match result.success() {
      Ok(_) => Ok(()),
      Err(LdapError::LdapResult { result: ref r }) if r.rc == 32 => Ok(()),
      Err(e) => Err(OperationError::DeleteFailed {
        dn: dn.to_string(),
        source: e,
      }),
    },
    Err(e) => Err(OperationError::DeleteFailed {
      dn: dn.to_string(),
      source: e,
    }),
  }
}

/// Returns the attribute map for an entry, or `None` if it does not exist.
pub async fn entry_get(
  ldap: &mut Ldap,
  dn: &str,
) -> Result<Option<HashMap<String, Vec<String>>>, OperationError> {
  match ldap
    .search(dn, ldap3::Scope::Base, "(objectClass=*)", vec!["*"])
    .await
  {
    Ok(result) => match result.success() {
      Ok((entries, _)) => Ok(
        entries
          .into_iter()
          .next()
          .map(|raw| SearchEntry::construct(raw).attrs),
      ),
      Err(LdapError::LdapResult { result: ref r }) if r.rc == 32 => Ok(None),
      Err(e) => Err(OperationError::SearchFailed {
        base: dn.to_string(),
        source: e,
      }),
    },
    Err(e) => Err(OperationError::SearchFailed {
      base: dn.to_string(),
      source: e,
    }),
  }
}

/// Lists direct-child DNs under `base_dn` (one-level search).
pub async fn entry_list(
  ldap: &mut Ldap,
  base_dn: &str,
) -> Result<Vec<String>, OperationError> {
  match ldap
    .search(base_dn, ldap3::Scope::OneLevel, "(objectClass=*)", vec!["1.1"])
    .await
  {
    Ok(result) => match result.success() {
      Ok((entries, _)) => Ok(
        entries
          .into_iter()
          .map(|raw| SearchEntry::construct(raw).dn)
          .collect(),
      ),
      Err(LdapError::LdapResult { result: ref r }) if r.rc == 32 => {
        Ok(Vec::new())
      }
      Err(e) => Err(OperationError::SearchFailed {
        base: base_dn.to_string(),
        source: e,
      }),
    },
    Err(e) => Err(OperationError::SearchFailed {
      base: base_dn.to_string(),
      source: e,
    }),
  }
}
