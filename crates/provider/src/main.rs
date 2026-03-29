use nix_hapi_provider_ldap_lib::LdapProvider;

fn main() {
  if let Err(e) = nix_hapi_lib::provider_host::run(LdapProvider) {
    eprintln!("nix-hapi-provider-ldap: {e}");
    std::process::exit(1);
  }
}
