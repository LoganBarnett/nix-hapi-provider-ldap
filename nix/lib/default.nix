# LDAP-specific helpers for constructing valid nix-hapi desired state.
# These enforce required fields at Nix eval time — a missing argument is a Nix
# error.  Plain string values are auto-wrapped as mkManaged; values already
# tagged with __nixhapi (e.g. mkInitial, mkManagedFromPath) pass through.
let
  # Wraps a plain string as a managed field value.  Already-tagged values
  # (attrsets with __nixhapi) are returned unchanged.
  ensureManaged = v:
    if builtins.isAttrs v && v ? __nixhapi
    then v
    else {
      __nixhapi = "managed";
      value = v;
    };

  # Applies ensureManaged to every value in an attrset.
  ensureManagedAttrs = builtins.mapAttrs (_: ensureManaged);
in {
  # Constructs a complete LDAP provider scope with config metadata.
  # Config fields accept plain strings (auto-wrapped as managed) or
  # pre-tagged values (mkManagedFromPath, mkInitial, etc.).
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
        provider = {
          type = "ldap";
          url = ensureManaged url;
          baseDn = ensureManaged baseDn;
          bindDn = ensureManaged bindDn;
          bindPassword = ensureManaged bindPassword;
        };
      }
      // (
        if ignore != []
        then {inherit ignore;}
        else {}
      );
    inherit users groups;
  };

  # Validates required inetOrgPerson fields at eval time.  Plain strings are
  # auto-wrapped as managed; use mkInitial/mkManagedFromPath etc. to override.
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
    ensureManagedAttrs {inherit cn sn mail userPassword;}
    // (
      if loginShell != null
      then ensureManagedAttrs {inherit loginShell;}
      else {}
    )
    // (
      if description != null
      then ensureManagedAttrs {inherit description;}
      else {}
    )
    // ensureManagedAttrs extra;

  mkLdapGroup = {
    description,
    members ? [],
  }: {
    description = ensureManaged description;
    inherit members;
  };
}
