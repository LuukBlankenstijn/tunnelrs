{
  lib,
  dockerTools,
  cacert,
  packages,
}:

let
  mkImage =
    package: extraContents:
    dockerTools.buildLayeredImage {
      name = package.pname;
      tag = "latest";
      contents = [ cacert ] ++ extraContents;
      config = {
        Entrypoint = [ (lib.getExe package) ];
        User = "65532:65532";
        Env = [ "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt" ];
      };
    };
in
{
  tunnelrs-server-image = mkImage packages.tunnelrs-server [ packages.tunnelrs-ctl ];
  tunnelrs-connector-image = mkImage packages.tunnelrs-connector [ ];
  tunnelrs-operator-image = mkImage packages.tunnelrs-operator [ ];
}
