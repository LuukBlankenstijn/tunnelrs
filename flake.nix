{
  description = "tunnelrs";

  nixConfig = {
    extra-substituters = [ "https://luukblankenstijn.cachix.org" ];
    extra-trusted-public-keys = [
      "luukblankenstijn.cachix.org-1:gRz/ypm8zdDizcdAuWD6UKLVBDeObfHsNDWoAka2WSw="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
    }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems =
        f:
        lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            }
          )
        );
      binaries =
        pkgs:
        import ./nix/packages.nix {
          craneLib = (crane.mkLib pkgs).overrideToolchain (
            p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml
          );
          inherit lib;
        };
      programs =
        pkgs:
        lib.removeAttrs (binaries pkgs) [
          "tests"
          "clippy"
        ];
    in
    {
      packages = forAllSystems (
        pkgs:
        programs pkgs
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          import ./nix/images.nix {
            inherit (pkgs) lib dockerTools cacert;
            packages = programs pkgs;
          }
        )
      );

      checks = forAllSystems (
        pkgs:
        {
          inherit (binaries pkgs) tests clippy;
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          module = import ./nix/tests/module.nix { inherit pkgs self; };
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
            pkgs.sqlx-cli
          ];
          shellHook = ''
            export DATABASE_URL="sqlite:$PWD/.sqlx-dev.db"
          '';
        };
      });

      overlays.default = final: _prev: {
        inherit (self.packages.${final.stdenv.hostPlatform.system})
          tunnelrs-server
          tunnelrs-connector
          tunnelrs-ctl
          tunnelrs-operator
          ;
      };

      nixosModules.default =
        { pkgs, lib, ... }:
        let
          packages = self.packages.${pkgs.stdenv.hostPlatform.system};
        in
        {
          imports = [ ./nix/module.nix ];
          services.tunnelrs.server.package = lib.mkDefault packages.tunnelrs-server;
          services.tunnelrs.server.ctlPackage = lib.mkDefault packages.tunnelrs-ctl;
          services.tunnelrs.connector.package = lib.mkDefault packages.tunnelrs-connector;
        };
    };
}
