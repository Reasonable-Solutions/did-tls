{
  description = "Build a cargo project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      advisory-db,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        inherit (pkgs) lib;

        craneLib = crane.mkLib pkgs;
        src = craneLib.cleanCargoSource ./.;

        # Common arguments can be set here to avoid repeating them later
        commonArgs = {
          inherit src;
          strictDeps = true;

          buildInputs = [
            # Add additional build inputs here
          ]
          ++ lib.optionals pkgs.stdenv.isDarwin [
            # Additional darwin specific inputs can be set here
            pkgs.libiconv
          ];

          # Additional environment variables can be set directly
          # MY_CUSTOM_VAR = "some value";
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate itself, reusing the dependency
        # artifacts from above.
        my-crate = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
          }
        );

        ping-pong-example = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            cargoBuildCommand = "cargo build --example ping_pong";
            doCheck = false;
            installPhase = ''
              runHook preInstall
              mkdir -p $out/bin
              if [ -f target/release/examples/ping_pong ]; then
                cp target/release/examples/ping_pong $out/bin/
              else
                found="$(find target -path '*/release/examples/ping_pong' -type f | head -n1)"
                if [ -z "$found" ]; then
                  echo "ping_pong example binary not found" >&2
                  exit 1
                fi
                cp "$found" $out/bin/ping_pong
              fi
              runHook postInstall
            '';
          }
        );

        demo-app = pkgs.writeShellApplication {
          name = "did-web-rpk-tls-demo";
          runtimeInputs = [
            pkgs.coreutils
            pkgs.gnused
          ];
          text = ''
            set -euo pipefail

            bin="${ping-pong-example}/bin/ping_pong"

            trap 'kill $(jobs -p) 2>/dev/null || true' EXIT INT TERM

            ${pkgs.coreutils}/bin/stdbuf -oL -eL "$bin" --host 127.0.0.1 --port 8443 \
              --did did:web:localhost%3A8443 \
              --peer-did did:web:localhost%3A9443 \
              --peer-addr 127.0.0.1:9443 \
              2>&1 | ${pkgs.gnused}/bin/sed -u 's/^/[service-a] /' &

            ${pkgs.coreutils}/bin/stdbuf -oL -eL "$bin" --host 127.0.0.1 --port 9443 \
              --did did:web:localhost%3A9443 \
              --peer-did did:web:localhost%3A8443 \
              --peer-addr 127.0.0.1:8443 \
              2>&1 | ${pkgs.gnused}/bin/sed -u 's/^/[service-b] /' &

            wait
          '';
        };
      in
      {
        checks = {
          # Build the crate as part of `nix flake check` for convenience
          inherit my-crate;
          inherit ping-pong-example;

          # Run clippy (and deny all warnings) on the crate source,
          # again, reusing the dependency artifacts from above.
          #
          # Note that this is done as a separate derivation so that
          # we can block the CI if there are issues here, but not
          # prevent downstream consumers from building our crate by itself.
          my-crate-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );

          my-crate-doc = craneLib.cargoDoc (
            commonArgs
            // {
              inherit cargoArtifacts;
              # This can be commented out or tweaked as necessary, e.g. set to
              # `--deny rustdoc::broken-intra-doc-links` to only enforce that lint
              env.RUSTDOCFLAGS = "--deny warnings";
            }
          );

          # Check formatting
          my-crate-fmt = craneLib.cargoFmt {
            inherit src;
          };

          my-crate-toml-fmt = craneLib.taploFmt {
            src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
            # taplo arguments can be further customized below as needed
            # taploExtraArgs = "--config ./taplo.toml";
          };

          # Audit dependencies
          my-crate-audit = craneLib.cargoAudit {
            inherit src advisory-db;
          };

          # Audit licenses
          my-crate-deny = craneLib.cargoDeny {
            inherit src;
          };

          # Run tests with cargo-nextest
          # Consider setting `doCheck = false` on `my-crate` if you do not want
          # the tests to run twice
          my-crate-nextest = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
              cargoNextestPartitionsExtraArgs = "--no-tests=pass";
            }
          );
        };

        packages = {
          default = my-crate;
          ping-pong-example = ping-pong-example;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = demo-app;
        };
        apps.demo = flake-utils.lib.mkApp {
          drv = demo-app;
        };

        devShells.default = craneLib.devShell {
          # Inherit inputs from checks.
          checks = self.checks.${system};

          # Additional dev-shell environment variables can be set directly
          # MY_CUSTOM_DEVELOPMENT_VAR = "something else";

          # Extra inputs can be added here; cargo and rustc are provided by default.
          packages = [
            pkgs.rust-analyzer
          ];
        };
      }
    );
}
