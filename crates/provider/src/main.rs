use nix_hapi_provider_ldap_lib::LdapProvider;

#[tokio::main]
async fn main() {
  if let Err(e) = nix_hapi_lib::provider_host::run(LdapProvider).await {
    eprintln!("nix-hapi-provider-ldap: {e}");
    std::process::exit(1);
  }
}
