{
  description = "LDAP provider for nix-hapi";
  inputs = {
    # LLM: Do NOT change this URL unless explicitly directed. This is the
    # correct format for nixpkgs stable (25.11 is correct, not nixos-25.11).
    nixpkgs.url = "github:NixOS/nixpkgs/25.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    crane,
  } @ inputs: let
    forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    overlays = [
      (import rust-overlay)
    ];
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        overlays = overlays;
      };

    # ============================================================================
    # WORKSPACE CRATES CONFIGURATION
    # ============================================================================
    workspaceCrates = {
      provider = {
        name = "nix-hapi-provider-ldap";
        binary = "nix-hapi-provider-ldap";
        description = "LDAP provider binary for nix-hapi";
      };

      # Note: The 'lib' crate is not included here as it doesn't produce a
      # binary.
    };

    # Development shell packages.
    devPackages = pkgs: let
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [
          # For rust-analyzer and others.  See
          # https://nixos.wiki/wiki/Rust#Shell.nix_example for some details.
          "rust-src"
          "rust-analyzer"
          "rustfmt"
        ];
      };
      # On some platforms slapd lives in libexec rather than bin.
      # symlinkJoin mirrors the full openldap tree and adds a bin/slapd
      # symlink so that `which slapd` returns a path whose grandparent is
      # the package root, which is what TestLdapServer.find_schema_dir()
      # expects when locating etc/schema/.
      openldapWithSlapd = pkgs.symlinkJoin {
        name = "openldap-with-slapd-in-bin";
        paths = [pkgs.openldap];
        postBuild = ''
          ln -sf ${pkgs.openldap}/libexec/slapd $out/bin/slapd
        '';
      };
    in [
      rust
      pkgs.cargo-sweep
      pkgs.pkg-config
      pkgs.openssl
      pkgs.jq
      # OpenLDAP for integration tests; openldapWithSlapd ensures slapd is on
      # PATH and that the schema directory is reachable via the standard
      # grandparent-of-binary heuristic in TestLdapServer.
      openldapWithSlapd
      # Unified formatter and language-specific formatters
      pkgs.treefmt
      pkgs.alejandra
      pkgs.elmPackages.elm-format
      pkgs.nodePackages.prettier
    ];
  in {
    lib = import ./nix/lib/default.nix;

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
    in {
      default = pkgs.mkShell {
        buildInputs = devPackages pkgs;
        shellHook = ''
          echo "nix-hapi-provider-ldap development environment"
          echo ""
          echo "Available Cargo packages (use 'cargo build -p <name>'):"
          cargo metadata --no-deps --format-version 1 2>/dev/null | \
            jq -r '.packages[].name' | \
            sort | \
            sed 's/^/  • /' || echo "  Run 'cargo init' to get started"

          # Symlink cargo-husky hooks into .git/hooks/ using paths relative
          # to .git/hooks/ so the repo stays valid after moves or copies.
          _git_root=$(git rev-parse --show-toplevel 2>/dev/null)
          if [ -n "$_git_root" ] && [ "$(pwd)" = "$_git_root" ] && [ -d ".cargo-husky/hooks" ]; then
            for _hook in .cargo-husky/hooks/*; do
              [ -x "$_hook" ] || continue
              _name=$(basename "$_hook")
              _dest="$_git_root/.git/hooks/$_name"
              _target=$(${pkgs.coreutils}/bin/realpath --relative-to="$_git_root/.git/hooks" "$(pwd)/$_hook")
              if [ ! -L "$_dest" ] || [ "$(readlink "$_dest")" != "$_target" ]; then
                ln -sf "$_target" "$_dest"
                echo "Installed git hook: $_name -> $_target"
              fi
            done
          fi
        '';
      };
    });

    # ============================================================================
    # PACKAGES
    # ============================================================================
    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.stable.latest.default);

      # Common build arguments shared by all crates
      commonArgs = {
        src = craneLib.cleanCargoSource ./.;
        # LLM: Do NOT add darwin.apple_sdk.frameworks here - they were removed
        # in nixpkgs 25.11+. Use libiconv for Darwin builds instead.
        buildInputs = with pkgs;
          [
            openssl
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs.darwin; [
            libiconv
          ]);
        nativeBuildInputs = with pkgs; [
          pkg-config
        ];
        # Run only unit tests (--lib --bins), skip integration tests in tests/ directories
        # Integration tests may require external services not available in Nix sandbox
        # Full test suite can be run locally with 'cargo test --all'
        cargoTestExtraArgs = "--lib --bins";
      };

      # Build individual crate packages from workspaceCrates.  When a
      # per-crate file exists under nix/packages/, it is used instead of
      # the generic crane build; this lets individual crates carry custom
      # build options without cluttering the top-level flake.
      cratePackages =
        pkgs.lib.mapAttrs (
          key: crate: let
            pkgFile = ./. + "/nix/packages/${key}.nix";
          in
            if builtins.pathExists pkgFile
            then import pkgFile {inherit craneLib commonArgs pkgs;}
            else
              craneLib.buildPackage (commonArgs
                // {
                  pname = crate.name;
                  cargoExtraArgs = "-p ${crate.name}";
                })
        )
        workspaceCrates;
    in
      cratePackages
      // {
        default = craneLib.buildPackage (commonArgs // {pname = "nix-hapi-provider-ldap";});
      });

    # ============================================================================
    # APPS
    # ============================================================================
    apps = forAllSystems (system: let
      pkgs = pkgsFor system;
    in
      pkgs.lib.mapAttrs (key: crate: {
        type = "app";
        program = "${self.packages.${system}.${key}}/bin/${crate.binary}";
      })
      workspaceCrates);
  };
}
