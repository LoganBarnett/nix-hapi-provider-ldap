# Evaluates the module against a sample configuration and compares the emitted
# desired-state tree with a hand-written fixture, then asserts that each
# misconfiguration the module guards against fails to evaluate.  Returns one
# derivation for `checks`.
{
  pkgs,
  self,
  nixHapiLib,
}: let
  inherit (pkgs) lib;

  # The engine's own module cannot be imported here: it defines
  # `systemd.services` behind `mkIf`, and the module system rejects
  # definitions for undeclared options even when the condition is false.
  # This stub declares just the option the provider module writes to.
  stub = {lib, ...}: {
    options.services.nix-hapi.trees = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          desiredState = lib.mkOption {type = (pkgs.formats.json {}).type;};
          providers = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
          };
        };
      });
      default = {};
    };
  };

  # Only `desiredState` is read, so the provider package is never built.
  evalDesired = modules:
    (lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules =
        [
          (import ../modules/common.nix {inherit self nixHapiLib;})
          stub
          {services.nix-hapi-ldap.package = pkgs.hello;}
        ]
        ++ modules;
    })
    .config
    .services
    .nix-hapi
    .trees
    .ldap
    .desiredState;

  sample = import ./sample.nix {inherit nixHapiLib;};

  actual =
    pkgs.writeText "nix-hapi-ldap-module-actual.json"
    (builtins.toJSON (evalDesired [sample]));

  # Each case is merged into the sample and must fail to evaluate.  The
  # collision spells an existing key with different case and trailing
  # whitespace, so it also proves DN normalisation.
  negatives = let
    proton = "dc=proton,dc=lan";
  in {
    dn-collision = {
      services.nix-hapi-ldap.servers.proton.entries.${proton}.entries."OU=People ".objectClass = ["top"];
    };
    multi-rdn-key = {
      services.nix-hapi-ldap.servers.proton.entries.${proton}.entries."uid=carol,ou=staff".objectClass = ["top"];
    };
    key-without-attribute = {
      services.nix-hapi-ldap.servers.proton.entries."proton".objectClass = ["top"];
    };
    wrong-provider-key-head = {
      services.nix-hapi-ldap.servers.proton.entries.${proton}.entries."ou=people".entries."uid=alice".__nixhapi.providerKey = ["uid=elsewhere,dc=proton,dc=lan"];
    };
    rename-on-parent = {
      services.nix-hapi-ldap.servers.proton.entries.${proton}.entries."ou=people".__nixhapi.providerKey = [
        "ou=people,dc=proton,dc=lan"
        "ou=users,dc=proton,dc=lan"
      ];
    };
    missing-object-class = {
      services.nix-hapi-ldap.servers.proton.entries.${proton}.entries."ou=empty" = {};
    };
  };

  tryEvalDeep = e: builtins.tryEval (builtins.deepSeq e e);
  unexpectedlyOk =
    lib.filterAttrs (_: extra: (tryEvalDeep (evalDesired [sample extra])).success)
    negatives;
in
  assert lib.assertMsg (unexpectedlyOk == {})
  "nix-hapi-ldap module: negative cases evaluated without error: ${
    lib.concatStringsSep ", " (builtins.attrNames unexpectedlyOk)
  }";
    pkgs.runCommand "nix-hapi-ldap-module-check" {
      nativeBuildInputs = [pkgs.jq];
    } ''
      jq --sort-keys . ${actual} > actual.json
      jq --sort-keys . ${./expected.json} > expected.json
      diff -u expected.json actual.json
      touch $out
    ''
