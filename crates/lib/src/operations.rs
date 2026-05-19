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

  #[error("Failed to rename entry '{from_dn}' -> '{to_dn}': {source}")]
  RenameFailed {
    from_dn: String,
    to_dn: String,
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

/// Renames an entry via LDAP modifyDN.  `new_rdn` is just the
/// leftmost RDN component (e.g. `uid=alicia`).  `new_sup` is
/// `Some(parent_dn)` when the entry is also moving between
/// containers, `None` for an in-place rename.  `delete_old` controls
/// whether the previous RDN's attribute value is dropped from the
/// entry's body — almost always true for our usage, since we want
/// `uid=alicia` to replace `uid=alice` in the entry's attributes.
pub async fn entry_modifydn(
  ldap: &mut Ldap,
  from_dn: &str,
  new_rdn: &str,
  delete_old: bool,
  new_sup: Option<&str>,
  to_dn: &str,
) -> Result<(), OperationError> {
  ldap
    .modifydn(from_dn, new_rdn, delete_old, new_sup)
    .await
    .map_err(|source| OperationError::RenameFailed {
      from_dn: from_dn.to_string(),
      to_dn: to_dn.to_string(),
      source,
    })?
    .success()
    .map(|_| ())
    .map_err(|source| OperationError::RenameFailed {
      from_dn: from_dn.to_string(),
      to_dn: to_dn.to_string(),
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

/// Lists direct-child entries under `base_dn` with their full
/// attribute maps in a single LDAP round trip.  Returns `(dn, attrs)`
/// pairs.  "No such object" (rc=32) on the base is reported as an
/// empty list so callers can treat a missing OU the same as an empty
/// OU.
pub async fn list_entries(
  ldap: &mut Ldap,
  base_dn: &str,
) -> Result<Vec<(String, HashMap<String, Vec<String>>)>, OperationError> {
  match ldap
    .search(base_dn, ldap3::Scope::OneLevel, "(objectClass=*)", vec!["*"])
    .await
  {
    Ok(result) => match result.success() {
      Ok((entries, _)) => Ok(
        entries
          .into_iter()
          .map(|raw| {
            let entry = SearchEntry::construct(raw);
            (entry.dn, entry.attrs)
          })
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
