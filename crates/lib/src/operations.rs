use ldap3::{LdapConn, LdapError, Mod, SearchEntry};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

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

/// Adds an entry.  Treats "already exists" (rc=68) as success for idempotency.
pub fn entry_add(
  ldap: &mut LdapConn,
  dn: &str,
  attrs: Vec<(&str, HashSet<&str>)>,
) -> Result<(), OperationError> {
  match ldap.add(dn, attrs) {
    Ok(result) => match result.success() {
      Ok(_) => Ok(()),
      Err(LdapError::LdapResult { result: ref r }) if r.rc == 68 => Ok(()),
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
pub fn entry_modify(
  ldap: &mut LdapConn,
  dn: &str,
  mods: Vec<Mod<&str>>,
) -> Result<(), OperationError> {
  ldap
    .modify(dn, mods)
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

/// Deletes an entry.  Treats "no such object" (rc=32) as success for idempotency.
pub fn entry_delete(
  ldap: &mut LdapConn,
  dn: &str,
) -> Result<(), OperationError> {
  match ldap.delete(dn) {
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
pub fn entry_get(
  ldap: &mut LdapConn,
  dn: &str,
) -> Result<Option<HashMap<String, Vec<String>>>, OperationError> {
  match ldap.search(dn, ldap3::Scope::Base, "(objectClass=*)", vec!["*"]) {
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

/// Lists all DNs under `base_dn` (subtree search).
pub fn entry_list(
  ldap: &mut LdapConn,
  base_dn: &str,
) -> Result<Vec<String>, OperationError> {
  match ldap.search(
    base_dn,
    ldap3::Scope::Subtree,
    "(objectClass=*)",
    vec!["1.1"],
  ) {
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
