# Shared NixOS / nix-darwin module for the LDAP nix-hapi provider.
#
# Declares typed options under `services.nix-hapi-ldap` and compiles them into
# the `services.nix-hapi.trees.ldap` tree the engine hands to the provider.
# The declaration is the record.  The provider owns every naming context the
# server publishes and deletes whatever it finds there that is not declared,
# apart from the naming contexts listed as unmanaged and the entries `ignore`
# exempts.  Entries nest in Nix as they nest in the directory, keyed by RDN
# beneath the naming contexts they live in, and the module flattens that tree
# into DN-keyed entries.  It knows nothing about LDAP schema; it composes DNs
# and normalises attribute values so desired and live state compare
# structurally.
#
# Imported by both `nixos.nix` and `darwin.nix`; a per-platform deviation
# belongs in the relevant wrapper, not here.
#
# Example:
#
#   services.nix-hapi.enable = true;
#   services.nix-hapi-ldap = {
#     enable = true;
#     servers."proton" = {
#       provider = {
#         url          = "ldaps://ldap.example.com";
#         bindDn       = "cn=admin,dc=example,dc=com";
#         bindPassword = mkManagedFromPath "/run/.../ldap-root-pass";
#       };
#       ignore = [ ''.__nixhapi.providerKey[0] == "cn=admin,dc=example,dc=com"'' ];
#       entries."dc=example,dc=com" = {
#         objectClass = [ "dcObject" "organization" ];
#         o = "Example";
#         entries."ou=people" = {
#           objectClass = [ "organizationalUnit" ];
#           entries."uid=alice" = {
#             objectClass  = [ "inetOrgPerson" ];
#             cn           = "Alice Smith";
#             sn           = "Smith";
#             userPassword = mkManagedFromPath "/run/.../alice-pw-hashed";
#             # Further values of the RDN attribute are login aliases.
#             uid          = [ "asmith" ];
#           };
#         };
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

  # -- Option types -------------------------------------------------------------

  # An entry is freeform LDAP attributes plus the engine's `__nixhapi` block, a
  # required objectClass, and its children.  Freeform values go through the
  # engine's `value` type, so bare literals and lists of literals coerce to
  # managed values.  The type recurses: a top-level key is a naming context
  # (an absolute DN), and each child's DN is its key followed by its parent's.
  mkEntryType = parentDn:
    lib.types.submodule ({name, ...}: let
      dn =
        if parentDn == null
        then name
        else "${name},${parentDn}";
    in {
      freeformType = lib.types.attrsOf value;
      options = {
        __nixhapi = nixHapiLib.mkNodeMetaOption {
          default = {providerKey = [dn];};
          description = ''
            Engine metadata.  The providerKey head defaults to the entry's
            DN; list prior DNs after it to declare a rename.  Only an entry
            without children may declare one: a renamed parent is recreated
            and each child carries the move.
          '';
        };
        objectClass = lib.mkOption {
          type = lib.types.nonEmptyListOf lib.types.str;
          description = ''
            The entry's object classes.  The module assumes no schema; the
            server decides which attributes they require or allow.
          '';
        };
        entries = lib.mkOption {
          type = lib.types.attrsOf (mkEntryType dn);
          default = {};
          description = ''
            Child entries keyed by RDN.  Nesting is DN composition, so the
            shape of this attrset is the shape of the directory.
          '';
        };
      };
    });

  providerCredsType = lib.types.submodule {
    options = {
      url = lib.mkOption {
        type = value;
        description = "LDAP server URL (ldap:// or ldaps://).";
      };
      bindDn = lib.mkOption {
        type = value;
        description = ''
          Bind DN for the account performing reconciliation.  It needs write
          access to every managed naming context.
        '';
      };
      bindPassword = lib.mkOption {
        type = value;
        description = "Bind password, typically wrapped via mkManagedFromPath.";
      };
    };
  };

  serverType = lib.types.submodule {
    options = {
      provider = lib.mkOption {
        type = providerCredsType;
        description = "LDAP server connection details.";
      };
      unmanagedNamingContexts = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = ["cn=config" "cn=monitor"];
        description = ''
          Naming contexts the provider neither reads nor writes.  The defaults
          are OpenLDAP's configuration and monitoring trees: the server's own
          machinery rather than directory data.
        '';
      };
      ignore = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = ''
          jq expressions matching live entries the reconciler must never delete,
          such as the account it binds as.
        '';
      };
      entries = lib.mkOption {
        type = lib.types.attrsOf (mkEntryType null);
        default = {};
        description = ''
          The directory, keyed by naming context and then by RDN at each level.
          Everything the server holds in a managed naming context that is not
          declared here is deleted unless `ignore` matches it.
        '';
      };
    };
  };

  # -- DN helpers ---------------------------------------------------------------

  trim = s: let
    m = builtins.match "[[:space:]]*(.*[^[:space:]])[[:space:]]*" s;
  in
    if m == null
    then ""
    else builtins.head m;

  # Comparison form of a DN: lowercased, no whitespace around `,` or `=`.
  # LDAP matches the naming attributes this module meets case-insensitively,
  # so spellings that differ only this way name the same entry.  Never
  # emitted, since lowercasing an RDN would change the stored naming value.
  normaliseDn = dn:
    lib.toLower (lib.concatStrings (map (part:
      if builtins.isList part
      then builtins.head part
      else part) (builtins.split "[[:space:]]*([,=])[[:space:]]*" dn)));

  # Leftmost RDN and parent of a DN, split at the first unescaped comma; null
  # for a single RDN.
  splitFirstRdn = dn: let
    m = builtins.match ''^((\\.|[^,\\])*),(.*)$'' dn;
  in
    if m == null
    then null
    else {
      rdn = builtins.elemAt m 0;
      parent = builtins.elemAt m 2;
    };

  # The RDN as `{attr; value;}`, trimmed; null when the DN has no `=`.
  rdnOf = dn: let
    split = splitFirstRdn dn;
    first =
      if split == null
      then dn
      else split.rdn;
    m = builtins.match "([^=]*)=(.*)" first;
  in
    if m == null
    then null
    else {
      attr = trim (builtins.elemAt m 0);
      value = trim (builtins.elemAt m 1);
    };

  # -- Wire projection ----------------------------------------------------------

  filterNulls = lib.filterAttrs (_: v: v != null);

  # A multi-valued attribute as live.rs projects it: empty -> null (stripped
  # by `filterNulls`), one -> the bare value, several -> sorted and
  # deduplicated.  LDAP attribute values are sets, and keeping both
  # projections in lockstep is what makes the engine's structural compare
  # idempotent.
  valuesToWire = values: let
    sorted = lib.sort builtins.lessThan (lib.unique values);
  in
    if sorted == []
    then null
    else if builtins.length sorted == 1
    then builtins.head sorted
    else sorted;

  # Live state is strings, and LDAP spells booleans TRUE and FALSE.
  scalarToWire = v:
    if builtins.isBool v
    then
      (
        if v
        then "TRUE"
        else "FALSE"
      )
    else if builtins.isInt v || builtins.isFloat v
    then toString v
    else v;

  isInline = v:
    builtins.isAttrs v
    && builtins.elem (v.__nixhapi or null) ["managed" "initial"];

  # Normalises the payload of an inline tagged value.  Path-, env- and
  # derived-backed values have no payload at evaluation time and pass
  # through.
  attrToWire = v:
    if !(isInline v)
    then v
    else if builtins.isList v.value
    then
      (
        let
          wire = valuesToWire (map scalarToWire v.value);
        in
          if wire == null
          then null
          else v // {value = wire;}
      )
    else v // {value = scalarToWire v.value;};

  # Drops the RDN value from the RDN attribute, as live state does; an entry
  # whose aliases list its naming value would otherwise modify forever.
  elideRdnValue = dn: body: let
    rdn = rdnOf dn;
    isRdnAttr = k: rdn != null && lib.toLower k == lib.toLower rdn.attr;
    isRdnValue = x:
      builtins.isString x && lib.toLower x == lib.toLower rdn.value;
    elide = v:
      if !(isInline v)
      then v
      else if builtins.isList v.value
      then v // {value = builtins.filter (x: !(isRdnValue x)) v.value;}
      else if isRdnValue v.value
      then null
      else v;
  in
    lib.mapAttrs (k: v:
      if isRdnAttr k
      then elide v
      else v)
    body;

  entryToWire = dn: body:
    filterNulls (lib.mapAttrs (_: attrToWire) (elideRdnValue dn (
      removeAttrs body ["__nixhapi" "objectClass" "entries"]
      // {objectClass = nixHapiLib.mkManaged body.objectClass;}
    )))
    // {inherit (body) __nixhapi;};

  # -- Compile one server -------------------------------------------------------

  serverToTree = serverName: server: let
    optPath = ''services.nix-hapi-ldap.servers."${serverName}"'';
    fail = origin: message: throw "${optPath}.${origin}: ${message}";

    # One record per declared entry, at every depth, carrying where it was
    # declared so an error can name it.  Top-level keys are absolute DNs.
    flatten = parentDn: originPrefix: entries:
      lib.concatLists (lib.mapAttrsToList (key: body: let
        dn =
          if parentDn == null
          then key
          else "${key},${parentDn}";
        origin = ''${originPrefix}entries."${key}"'';
      in
        [
          {
            inherit dn origin body key;
            topLevel = parentDn == null;
          }
        ]
        ++ flatten dn "${origin}." body.entries)
      entries);
    records = flatten null "" server.entries;

    checkKeyShape = r:
      if !(lib.hasInfix "=" r.key)
      then
        fail r.origin ''
          entry keys must be a DN component such as "uid=alice"; this key has no "=".''
      else if !r.topLevel && splitFirstRdn r.key != null
      then
        fail r.origin ''
          nested entry keys must be a single RDN; nest entries to express depth.''
      else r;
    checkProviderKeyHead = r: let
      head = builtins.head r.body.__nixhapi.providerKey;
    in
      if head == r.dn
      then r
      else
        fail r.origin ''
          __nixhapi.providerKey head must be the composed DN "${r.dn}" (got "${toString head}").  Keep the composed DN first and list prior DNs after it to declare a rename.'';
    # The provider renames leaf entries only, the one form every server
    # supports.  A parent is recreated; its children carry the move.
    checkLeafRename = r:
      if builtins.length r.body.__nixhapi.providerKey > 1 && r.body.entries != {}
      then
        fail r.origin ''
          an entry with children cannot declare a rename.  Drop the history here and declare it on each child instead: the parent is recreated and the children are moved.''
      else r;

    # Grouping by normalised DN forces every record through the checks above
    # and is where differently spelled keys meet.  `listToAttrs` keeps the
    # first duplicate silently, so it must run after this.
    checkCollisions = rs: let
      dupes =
        lib.filterAttrs (_: g: builtins.length g > 1)
        (lib.groupBy (r: normaliseDn r.dn) rs);
      render = lib.concatStringsSep "\n" (lib.mapAttrsToList (dn: g:
        "  ${dn}:\n"
        + lib.concatMapStringsSep "\n" (r: "    - ${r.origin}") g)
      dupes);
    in
      if dupes == {}
      then rs
      else
        throw ''
          ${optPath}: the same LDAP entry is declared more than once.
          ${render}
          Each entry may be declared by exactly one key.'';

    checked =
      checkCollisions
      (map (r: checkLeafRename (checkProviderKeyHead (checkKeyShape r)))
        records);

    entries =
      builtins.listToAttrs
      (map (r: lib.nameValuePair r.dn (entryToWire r.dn r.body)) checked);
  in {
    __nixhapi =
      {
        provider = {
          type = "ldap";
          inherit (server.provider) url bindDn bindPassword;
          unmanagedNamingContexts =
            nixHapiLib.mkManaged server.unmanagedNamingContexts;
        };
      }
      // lib.optionalAttrs (server.ignore != []) {inherit (server) ignore;};
    inherit entries;
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

    servers = lib.mkOption {
      type = lib.types.attrsOf serverType;
      default = {};
      description = ''
        One block per LDAP server: its connection and the entries it holds.  The
        attribute key is an arbitrary name.  Entries for one server are
        accumulated across all modules that contribute to it.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.nix-hapi.trees.ldap = {
      providers.ldap = lib.getExe cfg.package;
      desiredState = lib.mapAttrs serverToTree cfg.servers;
    };
  };
}
