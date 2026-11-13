use ldap3::{Ldap, LdapError, Mod, Scope, SearchEntry};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum OperationError {
  #[error("Failed to add entry '{dn}': {source}")]
  Add {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to modify entry '{dn}'{hint}: {source}")]
  Modify {
    dn: String,
    hint: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to delete entry '{dn}': {source}")]
  Delete {
    dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to rename entry '{from_dn}' -> '{to_dn}': {source}")]
  Rename {
    from_dn: String,
    to_dn: String,
    #[source]
    source: LdapError,
  },

  #[error("Failed to search under '{base}' with filter '{filter}': {source}")]
  Search {
    base: String,
    filter: String,
    #[source]
    source: LdapError,
  },

  #[error(
    "Failed to read the server's root DSE for its naming contexts: {source}"
  )]
  RootDse {
    #[source]
    source: LdapError,
  },

  #[error(
    "The server's root DSE lists no naming contexts, so there is nothing to \
     own"
  )]
  NoNamingContexts,
}

/// The trees the server serves, as its root DSE publishes them in
/// `namingContexts` (RFC 4512, section 5.1).
pub async fn naming_contexts(
  ldap: &mut Ldap,
) -> Result<Vec<String>, OperationError> {
  let (entries, _) = ldap
    .search("", Scope::Base, "(objectClass=*)", vec!["namingContexts"])
    .await
    .map_err(|source| OperationError::RootDse { source })?
    .success()
    .map_err(|source| OperationError::RootDse { source })?;
  let contexts: Vec<String> = entries
    .into_iter()
    .map(SearchEntry::construct)
    .flat_map(|entry| {
      entry
        .attrs
        .into_iter()
        .filter(|(attr, _)| attr.eq_ignore_ascii_case("namingContexts"))
        .flat_map(|(_, values)| values)
    })
    .collect();
  (!contexts.is_empty())
    .then_some(contexts)
    .ok_or(OperationError::NoNamingContexts)
}

fn modify_error(dn: &str, source: LdapError) -> OperationError {
  OperationError::Modify {
    dn: dn.to_string(),
    hint: modify_error_detail(&source),
    source,
  }
}

/// A hint for the schema-related result codes a Modify commonly hits.  The
/// provider assumes no schema, so these are the server's rules surfacing.
fn modify_error_detail(err: &LdapError) -> String {
  match err {
    LdapError::LdapResult { result } => match result.rc {
      64 => " (naming violation: the RDN attribute must keep its naming value)",
      65 => {
        " (object class violation: an attribute is not allowed by the entry's \
         object classes, or a required attribute is missing)"
      }
      69 => {
        " (object class modifications prohibited: a structural object class \
         cannot change in place; delete and re-add the entry)"
      }
      _ => "",
    },
    _ => "",
  }
  .to_string()
}

fn search_error(base: &str, filter: &str, source: LdapError) -> OperationError {
  OperationError::Search {
    base: base.to_string(),
    filter: filter.to_string(),
    source,
  }
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
      Err(e) => Err(OperationError::Add {
        dn: dn.to_string(),
        source: e,
      }),
    },
    Err(e) => Err(OperationError::Add {
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
    .map_err(|source| modify_error(dn, source))?
    .success()
    .map(|_| ())
    .map_err(|source| modify_error(dn, source))
}

/// Renames an entry via LDAP modifyDN.  `new_rdn` is just the
/// leftmost RDN component (e.g. `uid=alicia`).  `new_sup` is
/// `Some(parent_dn)` when the entry is also moving between
/// containers, `None` for an in-place rename.  `delete_old` controls
/// whether the previous RDN's attribute value is dropped from the
/// entry's body, almost always true for our usage, since we want
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
    .map_err(|source| OperationError::Rename {
      from_dn: from_dn.to_string(),
      to_dn: to_dn.to_string(),
      source,
    })?
    .success()
    .map(|_| ())
    .map_err(|source| OperationError::Rename {
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
      Err(e) => Err(OperationError::Delete {
        dn: dn.to_string(),
        source: e,
      }),
    },
    Err(e) => Err(OperationError::Delete {
      dn: dn.to_string(),
      source: e,
    }),
  }
}

/// Runs one search and returns every matching entry as `(dn, attrs)` with
/// its full attribute map, in a single round trip.  "No such object" (rc=32)
/// on the base is reported as an empty list, so a container that does not
/// exist yet reads the same as an empty one; the warning is there because it
/// is also what a mistyped search base looks like.
pub async fn list_entries(
  ldap: &mut Ldap,
  base_dn: &str,
  scope: Scope,
  filter: &str,
) -> Result<Vec<(String, HashMap<String, Vec<String>>)>, OperationError> {
  match ldap.search(base_dn, scope, filter, vec!["*"]).await {
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
        warn!(
          base = %base_dn,
          filter = %filter,
          "Search base does not exist on the server; treating it as empty"
        );
        Ok(Vec::new())
      }
      Err(e) => Err(search_error(base_dn, filter, e)),
    },
    Err(e) => Err(search_error(base_dn, filter, e)),
  }
}
