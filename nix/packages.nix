{
  lib,
  craneLib,
}:

let
  root = ../.;

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (craneLib.fileset.commonCargoSources root)
      ../crates/server/migrations
      ../.sqlx
    ];
  };

  commonArgs = {
    inherit src;
    pname = "tunnelrs";
    version = (lib.importTOML ../Cargo.toml).workspace.package.version;
    strictDeps = true;
    SQLX_OFFLINE = "true";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  mkBin =
    name: description:
    craneLib.buildPackage (
      commonArgs
      // {
        inherit cargoArtifacts;
        pname = "tunnelrs-${name}";
        cargoExtraArgs = "--locked -p tunnelrs-${name}";
        doCheck = false;
        meta = {
          inherit description;
          homepage = "https://github.com/LuukBlankenstijn/tunnelrs";
          mainProgram = "tunnelrs-${name}";
          platforms = lib.platforms.unix;
        };
      }
    );
in
{
  tunnelrs-server = mkBin "server" "tunnelrs hub: holds grants and routes, forwards visitor traffic to connectors";
  tunnelrs-connector = mkBin "connector" "tunnelrs connector: dials the server and forwards data streams to local backends";
  tunnelrs-ctl = mkBin "ctl" "tunnelrs admin CLI";
  tunnelrs-operator = mkBin "operator" "tunnelrs Kubernetes operator: turns routes into ingress objects";

  tests = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });
  clippy = craneLib.cargoClippy (
    commonArgs
    // {
      inherit cargoArtifacts;
      cargoClippyExtraArgs = "--workspace --all-targets -- --deny warnings";
    }
  );
}
