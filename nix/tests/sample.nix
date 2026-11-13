# A configuration exercising every projection the module performs.  The
# fixture beside it is what the provider must receive.
{nixHapiLib}: let
  inherit (nixHapiLib) mkManagedFromPath mkInitialFromPath;
in {
  services.nix-hapi-ldap = {
    enable = true;
    servers."proton" = {
      provider = {
        url = "ldaps://ldap.proton.lan";
        bindDn = "cn=admin,dc=proton,dc=lan";
        bindPassword = mkManagedFromPath "/run/agenix/ldap-root-pw";
      };
      ignore = [
        ''.__nixhapi.providerKey[0] == "cn=admin,dc=proton,dc=lan"''
      ];

      # The naming context is an entry like any other; `dc` is its RDN
      # attribute and is implied.
      entries."dc=proton,dc=lan" = {
        objectClass = ["dcObject" "organization"];
        o = "Proton";
        entries = {
          # Lists arrive out of order to prove sorting, `uid` lists the
          # naming value to prove elision, the number and the boolean prove
          # stringification, and the empty list is stripped.
          "ou=people" = {
            objectClass = ["organizationalUnit" "top"];
            entries = {
              "uid=alice" = {
                objectClass = ["inetOrgPerson" "top" "person"];
                cn = "Alice Smith";
                sn = "Smith";
                mail = ["alice@proton.lan" "a.smith@proton.lan"];
                uid = ["asmith" "alice"];
                uidNumber = 1001;
                shadowInactive = true;
                telephoneNumber = [];
                userPassword = mkInitialFromPath "/run/agenix/alice-pw-hashed";
              };
              # A rename: the head is the composed DN, the prior DN follows.
              "uid=bobby" = {
                objectClass = ["inetOrgPerson"];
                cn = "Bob Jones";
                sn = "Jones";
                __nixhapi.providerKey = [
                  "uid=bobby,ou=people,dc=proton,dc=lan"
                  "uid=bob,ou=people,dc=proton,dc=lan"
                ];
              };
            };
          };

          # Three levels of nesting prove DN composition.
          "ou=services" = {
            objectClass = ["organizationalUnit"];
            entries."ou=web" = {
              objectClass = ["organizationalUnit"];
              entries."cn=gitea" = {
                objectClass = ["applicationProcess"];
                description = "Gitea service";
              };
            };
          };

          "cn=replicator" = {
            objectClass = ["simpleSecurityObject" "organizationalRole"];
            userPassword = mkManagedFromPath "/run/agenix/replicator-pw";
          };
        };
      };
    };
  };
}
