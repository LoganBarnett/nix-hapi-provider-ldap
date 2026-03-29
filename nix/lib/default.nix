# LDAP-specific helpers for constructing valid nix-hapi desired state.
# These enforce required fields at Nix eval time — a missing argument is a Nix
# error.  Field values should be wrapped with nix-hapi's mkManaged/mkInitial
# etc. by the consumer.
{
  # Constructs a complete LDAP provider scope with config metadata.
  mkLdapProvider = {
    url,
    baseDn,
    bindDn,
    bindPassword,
    users ? {},
    groups ? {},
    ignore ? [],
  }: {
    __nixhapi =
      {
        type = "ldap";
        inherit url baseDn bindDn bindPassword;
      }
      // (
        if ignore != []
        then {inherit ignore;}
        else {}
      );
    inherit users groups;
  };

  # Validates required inetOrgPerson fields at eval time.
  mkLdapUser = {
    cn,
    sn,
    mail,
    userPassword,
    loginShell ? null,
    description ? null,
    ...
  } @ attrs: let
    extra = builtins.removeAttrs attrs [
      "cn"
      "sn"
      "mail"
      "userPassword"
      "loginShell"
      "description"
    ];
  in
    {inherit cn sn mail userPassword;}
    // (
      if loginShell != null
      then {inherit loginShell;}
      else {}
    )
    // (
      if description != null
      then {inherit description;}
      else {}
    )
    // extra;

  mkLdapGroup = {
    description,
    members ? [],
  }: {
    inherit description members;
  };
}
