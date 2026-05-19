# Shared NixOS / nix-darwin module for the LDAP nix-hapi provider.
#
# Declares typed options under `services.nix-hapi-ldap` and contributes a
# `services.nix-hapi.trees.ldap` tree to the engine.  Users write
# declarative config; the module translates it into the JSON the rust
# reconciler expects on stdin.
#
# Imported by both `nixos.nix` and `darwin.nix`.  The two platforms
# currently use identical option semantics — keeping the implementation
# in one file lets a per-platform deviation (different default package
# path, different service-supervision plumbing) be added later by
# editing only the relevant wrapper rather than diffing two near-copies.
#
# Example:
#
#   services.nix-hapi.enable = true;
#   services.nix-hapi-ldap = {
#     enable = true;
#     scopes."proton-ldap" = {
#       provider = {
#         url          = "ldaps://ldap.example.com";
#         baseDn       = "dc=example,dc=com";
#         bindDn       = "cn=admin,dc=example,dc=com";
#         bindPassword = mkManagedFromPath "/run/.../ldap-root-pass";
#       };
#       ignore = [ ];
#       users."alice" = {
#         cn           = "Alice Smith";
#         sn           = "alice";
#         mail         = "alice@example.com";
#         userPassword = mkManagedFromPath "/run/.../alice-pw-hashed";
#         # Multi-valued attributes via list literal:
#         objectClass  = [ "top" "person" "inetOrgPerson" ];
#       };
#       groups."engineering" = {
#         description = "Engineering team";
#         members     = [ "alice" "bob" ];
#       };
#     };
#   };
{
  self,
  nixHapiLib,
}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.nix-hapi-ldap;
  value = nixHapiLib.types.value;

  # Extracts the literal string from a value-typed (coercedTo) option.
  # Required for fields like baseDn that we need to substitute into DN
  # templates at evaluation time — path/env-backed bindings cannot be
  # resolved without the reconciler running.
  literalValue = field: v:
    v.value
    or (throw ''
      services.nix-hapi-ldap: ${field} must be a literal string value;
      path- or env-backed FieldValues cannot participate in DN
      composition at evaluation time.
    '');

  # Engine-owned `__nixhapi` schema reused for every keyed node.
  # `nixHapiLib.mkNodeMetaOption` carries the engine's canonical
  # validation (non-empty `providerKey`, jq-expression `dependsOn`,
  # strict on unknown sibling keys) so this module doesn't lockstep
  # its schema with the reconciler — see `provider-api.org` >
  # "Reserved-key discipline" in the engine docs for why.

  # User entry submodule.  Parameterised on the scope's `baseDn` so
  # the auto-composed `__nixhapi.providerKey` default can interpolate
  # the full entry DN at option-default time, matching the documented
  # engine pattern of "auto-derived head the user can override to
  # declare a rename."  Required attributes (cn, sn, mail,
  # userPassword) are typed; optional ones (loginShell, description)
  # default to null.  `freeformType = attrsOf value` admits arbitrary
  # additional LDAP attributes (uidNumber, telephoneNumber,
  # objectClass, …) without enumerating every possible RFC schema
  # field; each freeform value goes through the `value` type, so it
  # gets the same tagged-value validation and bare-literal coercion
  # (including list literals for multi-valued attributes).
  mkUserType = baseDn:
    lib.types.submodule ({name, ...}: {
      freeformType = lib.types.attrsOf value;
      options = {
        __nixhapi = nixHapiLib.mkNodeMetaOption {
          default = {
            providerKey = ["uid=${name},ou=users,${baseDn}"];
          };
          description = ''
            Engine metadata block.  Reserved namespace — anything in
            here is consumed by the nix-hapi engine during
            reconciliation, never written to the LDAP entry's
            attribute set.  Default sets the providerKey head to the
            entry's auto-composed DN; override `__nixhapi.providerKey`
            with a longer list (head first, prior DNs after) to
            declare a rename.
          '';
        };
        cn = lib.mkOption {
          type = value;
          description = "Common name (full display name).";
        };
        sn = lib.mkOption {
          type = value;
          description = "Surname.";
        };
        mail = lib.mkOption {
          type = value;
          description = "Email address.";
        };
        userPassword = lib.mkOption {
          type = value;
          description = ''
            Hashed password, typically wrapped via mkManagedFromPath or
            mkInitialFromPath pointing at an agenix-decrypted hash file.
          '';
        };
        loginShell = lib.mkOption {
          type = lib.types.nullOr value;
          default = null;
          description = "Optional POSIX login shell path.";
        };
        description = lib.mkOption {
          type = lib.types.nullOr value;
          default = null;
        };
      };
    });

  # Group entry.  `members` is structural (the list of user keys this
  # group claims), not a managed leaf — no value-type wrapping.  Same
  # `__nixhapi.providerKey` rename mechanism as users; the
  # auto-composed default uses `cn=` since groupOfNames is keyed by
  # cn.
  mkGroupType = baseDn:
    lib.types.submodule ({name, ...}: {
      options = {
        __nixhapi = nixHapiLib.mkNodeMetaOption {
          default = {
            providerKey = ["cn=${name},ou=groups,${baseDn}"];
          };
          description = ''
            Engine metadata block.  See `users.<uid>.__nixhapi` for
            the contract; same semantics apply here.
          '';
        };
        description = lib.mkOption {
          type = lib.types.nullOr value;
          default = null;
        };
        members = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
          description = "User keys that belong to this group.";
        };
      };
    });

  providerCredsType = lib.types.submodule {
    options = {
      url = lib.mkOption {
        type = value;
        description = "LDAP server URL (ldap:// or ldaps://).";
      };
      baseDn = lib.mkOption {
        type = value;
        description = "Base DN for users and groups.";
      };
      bindDn = lib.mkOption {
        type = value;
        description = "Bind DN for the admin account performing reconciliation.";
      };
      bindPassword = lib.mkOption {
        type = value;
        description = "Admin bind password, typically wrapped via mkManagedFromPath.";
      };
    };
  };

  # `scopeType` is the function-form submodule so we can read
  # `config.provider.baseDn` and thread it into the user/group
  # submodules — they need it at option-default time to compose the
  # auto-derived providerKey head.
  scopeType = lib.types.submodule ({config, ...}: let
    baseDn = literalValue "provider.baseDn" config.provider.baseDn;
  in {
    options = {
      provider = lib.mkOption {
        type = providerCredsType;
        description = "LDAP server connection details.";
      };
      ignore = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = ''
          jq expressions matching DNs the reconciler should leave
          unchanged on every apply (e.g. apex DNs, system accounts).
        '';
      };
      users = lib.mkOption {
        type = lib.types.attrsOf (mkUserType baseDn);
        default = {};
        description = ''
          Map of uid → user attributes.  Multiple modules may
          contribute users to the same scope; they merge per-uid and
          collisions on the same field error at evaluation time.
        '';
      };
      groups = lib.mkOption {
        type = lib.types.attrsOf (mkGroupType baseDn);
        default = {};
        description = ''
          Map of cn → group attributes.  Member lists from multiple
          modules contributing to the same group are NOT auto-merged
          at this layer (lists merge per the option's mergeFunction);
          aggregate at the call site if you need cross-module unions.
        '';
      };
    };
  });

  # Translate one typed scope into the JSON shape the rust reconciler
  # expects.  The scope's `__nixhapi` carries provider config (and
  # optionally an ignore list); each user/group node carries its own
  # `__nixhapi.providerKey` so the engine's diff can match desired↔live
  # at user/group granularity and detect renames via history entries.
  #
  # The submodule already places `__nixhapi` exactly where the wire
  # format wants it, so there is no lifting or namespace gymnastics
  # here — the JSON shape mirrors the Nix shape one-to-one.
  #
  # Wire-format choices the reconciler relies on:
  #   * `ignore` is omitted entirely when empty.
  #   * Per-user / per-group null-valued attributes (loginShell,
  #     description) are stripped rather than emitted as explicit
  #     nulls so the engine's field-level diff doesn't see a phantom
  #     change.
  #
  # The provider's diff lives on the wire side, not in Nix, so things
  # like objectClass synthesis stay in the rust binary; the Nix module
  # only emits what the user declared.
  filterNulls = lib.filterAttrs (_: v: v != null);

  # Body fields are everything outside `__nixhapi`, with explicit
  # nulls stripped.  The `__nixhapi` block flows through untouched.
  userToJson = user:
    filterNulls (removeAttrs user ["__nixhapi"])
    // {inherit (user) __nixhapi;};

  # `members` lists user keys; the wire form is `member` carrying the
  # composed DNs the LDAP server uses.  Shape mirrors `live.rs`'s
  # `normalise`: empty → null (stripped by `filterNulls`); single → a
  # bare string; multiple → a lexicographically sorted array.  Keeping
  # the desired-side projection in lockstep with the live-side
  # projection is what makes the engine's structural compare idempotent
  # on single-member groups instead of looping a no-op modify.
  membersToWire = baseDn: members: let
    dns =
      lib.sort builtins.lessThan
      (map (uid: "uid=${uid},ou=users,${baseDn}") members);
  in
    if dns == []
    then null
    else if builtins.length dns == 1
    then builtins.head dns
    else dns;

  groupToJson = baseDn: group:
    filterNulls (
      removeAttrs group ["__nixhapi" "members"]
      // {member = membersToWire baseDn group.members;}
    )
    // {inherit (group) __nixhapi;};

  scopeToTree = scope: let
    baseDn = literalValue "provider.baseDn" scope.provider.baseDn;
    meta =
      {
        provider = {
          type = "ldap";
          inherit (scope.provider) url baseDn bindDn bindPassword;
        };
      }
      // (lib.optionalAttrs (scope.ignore != []) {inherit (scope) ignore;});
  in {
    __nixhapi = meta;
    users = lib.mapAttrs (_: userToJson) scope.users;
    groups = lib.mapAttrs (_: groupToJson baseDn) scope.groups;
  };
in {
  options.services.nix-hapi-ldap = {
    enable = lib.mkEnableOption "LDAP reconciler via nix-hapi";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression ''nix-hapi-provider-ldap.packages.''${system}.default'';
      description = "The LDAP reconciler binary package.";
    };

    scopes = lib.mkOption {
      type = lib.types.attrsOf scopeType;
      default = {};
      description = ''
        Per-LDAP-server scopes.  The outer attribute key is an arbitrary
        scope name (LDAP doesn't have a canonical identifier the way DNS
        domains do).  Users and groups within a scope are accumulated
        across all modules that contribute to it.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.nix-hapi.trees.ldap = {
      providers.ldap = lib.getExe cfg.package;
      desiredState = lib.mapAttrs (_: scopeToTree) cfg.scopes;
    };
  };
}
