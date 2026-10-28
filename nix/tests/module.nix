{
  pkgs,
  self,
}:

let
  serverId = "b0336c1b518c5781d788e5c860afa8d6c2ec33553895fb0c86aa96c1f7eb47a1";
  connectorId = "c353891238df2d25b68e86d38ee9b9dd8ce2a9af9f417f9c58b08b1e8fb748a7";
  ctlId = "09fa6a5996a213923b32f2fca58cf565de0f91cbaf3dad86542be8f56c8ca62e";

  ctlConfig = (pkgs.formats.toml { }).generate "ctl.toml" {
    key_path = "${./keys/ctl.key}";
    server = {
      id = serverId;
      addrs = [ "127.0.0.1:7842" ];
    };
  };

  ctl = "tunnelrs-ctl --config ${ctlConfig}";
in
pkgs.testers.runNixOSTest {
  name = "tunnelrs-module";

  nodes.machine = {
    imports = [ self.nixosModules.default ];

    environment.systemPackages = [
      pkgs.curl
      pkgs.openssl
    ];

    services.tunnelrs.server = {
      enable = true;
      keyFile = "${./keys/server.key}";
      iroh.bind = "127.0.0.1:7842";
      adminKeys.${ctlId} = "admin";
    };

    services.tunnelrs.connector = {
      enable = true;
      keyFile = "${./keys/connector.key}";
      server = {
        id = serverId;
        addrs = [ "127.0.0.1:7842" ];
      };
      exposures = {
        "app.example.com".backend = "127.0.0.1:9000";
        "secure.example.com" = {
          backend = "127.0.0.1:9443";
          tls = "passthrough";
        };
      };
    };

    systemd.services.http-backend = {
      wantedBy = [ "multi-user.target" ];
      script = ''
        mkdir -p /srv/www
        echo hello-from-backend > /srv/www/index.html
        exec ${pkgs.python3}/bin/python3 -m http.server 9000 --bind 127.0.0.1 --directory /srv/www
      '';
    };

    systemd.services.tls-backend = {
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.openssl ];
      script = ''
        cd /tmp
        openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj /CN=secure.example.com
        exec openssl s_server -accept 9443 -cert cert.pem -key key.pem -www
      '';
    };
  };

  testScript = ''
    machine.wait_for_unit("tunnelrs-server.service")
    machine.wait_for_unit("tunnelrs-connector.service")
    machine.wait_for_open_port(9000)
    machine.wait_for_open_port(9443)
    machine.wait_for_open_port(8080)

    machine.wait_until_succeeds("${ctl} list | grep ${connectorId} | grep pending")
    machine.succeed("test \"$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: app.example.com' http://127.0.0.1:8080/)\" = 404")

    machine.succeed("${ctl} approve ${connectorId}")
    machine.wait_until_succeeds("curl -sf -H 'Host: app.example.com' http://127.0.0.1:8080/index.html | grep hello-from-backend")
    machine.succeed(
        "curl -sk --resolve secure.example.com:8443:127.0.0.1 https://secure.example.com:8443/ | grep -i 's_server'"
    )

    machine.succeed("systemctl reload tunnelrs-connector.service")
    machine.wait_until_succeeds("journalctl -u tunnelrs-connector.service | grep -i reload")

    machine.systemctl("stop tunnelrs-connector.service")
    machine.wait_until_succeeds("test \"$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: app.example.com' http://127.0.0.1:8080/)\" = 503")

    machine.systemctl("restart tunnelrs-server.service")
    machine.wait_for_open_port(8080)
    machine.wait_until_succeeds("${ctl} routes | grep app.example.com | grep offline")
    machine.succeed("test \"$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: app.example.com' http://127.0.0.1:8080/)\" = 503")

    machine.systemctl("start tunnelrs-connector.service")
    machine.wait_until_succeeds("curl -sf -H 'Host: app.example.com' http://127.0.0.1:8080/index.html | grep hello-from-backend")
  '';
}
