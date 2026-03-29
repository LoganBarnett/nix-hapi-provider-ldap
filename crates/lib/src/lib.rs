use nix_hapi_lib::{
  meta::NixHapiMeta,
  plan::{ApplyReport, ProviderPlan},
  provider::{Filter, Provider, ProviderError, ResolvedConfig},
};

pub struct LdapProvider;

impl Provider for LdapProvider {
  fn provider_type(&self) -> &str {
    "ldap"
  }

  fn sensitive_config_fields(&self) -> &[&str] {
    &["bind_password"]
  }

  fn list_live(
    &self,
    _config: &ResolvedConfig,
    _filters: &[Filter],
  ) -> Result<serde_json::Value, ProviderError> {
    todo!("Port from nix-hapi/crates/ldap/src/provider.rs")
  }

  fn plan(
    &self,
    _desired: &serde_json::Value,
    _live: &serde_json::Value,
    _meta: &NixHapiMeta,
    _config: &ResolvedConfig,
  ) -> Result<ProviderPlan, ProviderError> {
    todo!("Port from nix-hapi/crates/ldap/src/provider.rs")
  }

  fn apply(
    &self,
    _plan: &ProviderPlan,
    _config: &ResolvedConfig,
  ) -> Result<ApplyReport, ProviderError> {
    todo!("Port from nix-hapi/crates/ldap/src/provider.rs")
  }
}
