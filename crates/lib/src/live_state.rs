use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The live state of an LDAP directory as seen by the provider, structured
/// to mirror `LdapDesiredState` so the reconciler can diff the two directly.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LdapLiveState {
  /// Live users keyed by uid value (not full DN).
  pub users: HashMap<String, LiveEntry>,
  /// Live groups keyed by cn value (not full DN).
  pub groups: HashMap<String, LiveEntry>,
}

/// Attribute map for a single live LDAP entry.
pub type LiveEntry = HashMap<String, Vec<String>>;
