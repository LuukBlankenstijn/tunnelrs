{
  config,
  lib,
  pkgs,
  utils,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    optional
    types
    ;

  toml = pkgs.formats.toml { };
  serverCfg = config.services.tunnelrs.server;
  connectorCfg = config.services.tunnelrs.connector;

  credentialPath = service: "/run/credentials/${service}.service/key";

  keyPath =
    service: keyFile: if keyFile == null then "/var/lib/${service}/key" else credentialPath service;

  portOf = address: lib.toInt (lib.last (lib.splitString ":" address));

  keyFileOption = service: mkOption {
    type = types.nullOr (types.strMatching "/.+");
    default = null;
    example = "/run/agenix/${service}-key";
    description = ''
      File holding the iroh secret key (64 hex characters), passed to the service as a systemd
      credential so it may be readable by root only. When null the service generates a key in
      /var/lib/${service} on first start.
    '';
  };

  serverAddrOptions = {
    id = mkOption {
      type = types.str;
      description = "Endpoint ID (public key) of the tunnelrs server.";
    };
    relays = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "https://relay.example.com" ];
      description = "iroh relay URLs used to reach the server when direct UDP is not possible.";
    };
    addrs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "203.0.113.5:7842" ];
      description = "Direct UDP socket addresses of the server.";
    };
  };

  hardening = {
    DynamicUser = true;
    UMask = "0077";
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    CapabilityBoundingSet = [ "" ];
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
      "AF_NETLINK"
    ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
    ];
    Restart = "always";
    RestartSec = "5s";
  };

  serverConfigFile = toml.generate "tunnelrs-server.toml" {
    key_path = keyPath "tunnelrs-server" serverCfg.keyFile;
    database = "/var/lib/tunnelrs-server/state.db";
    http_listen = serverCfg.httpListen;
    tls_listen = serverCfg.tlsListen;
    offline_expiry_secs = serverCfg.offlineExpirySecs;
    iroh = {
      relays = serverCfg.iroh.relays;
    }
    // lib.optionalAttrs (serverCfg.iroh.bind != null) { inherit (serverCfg.iroh) bind; };
    admin_keys = lib.mapAttrsToList (id: role: { inherit id role; }) serverCfg.adminKeys;
  };

  connectorConfig = {
    key_path = keyPath "tunnelrs-connector" connectorCfg.keyFile;
    server = connectorCfg.server;
    expose = lib.mapAttrsToList (hostname: exposure: {
      inherit hostname;
      inherit (exposure) backend tls meta;
    }) connectorCfg.exposures;
  };
in
{
  options.services.tunnelrs = {
    server = {
      enable = mkEnableOption "the tunnelrs server";
      package = mkOption {
        type = types.package;
        description = "The tunnelrs-server package to use.";
      };
      ctlPackage = mkOption {
        type = types.package;
        description = "The tunnelrs-ctl package installed system-wide next to the server.";
      };
      keyFile = keyFileOption "tunnelrs-server";
      httpListen = mkOption {
        type = types.str;
        default = "127.0.0.1:8080";
        description = "host:port of the plain HTTP listener the edge sends terminate routes to.";
      };
      tlsListen = mkOption {
        type = types.str;
        default = "127.0.0.1:8443";
        description = "host:port of the TLS listener the edge sends passthrough routes to.";
      };
      offlineExpirySecs = mkOption {
        type = types.ints.positive;
        default = 86400;
        description = "Seconds an offline route keeps its hostname before it is withdrawn.";
      };
      iroh = {
        bind = mkOption {
          type = types.nullOr types.str;
          default = "0.0.0.0:7842";
          description = "UDP host:port for direct iroh connections; null binds a random port and relies on relays.";
        };
        relays = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "https://relay.example.com" ];
          description = "iroh relay URLs the server keeps a connection to.";
        };
      };
      adminKeys = mkOption {
        type = types.attrsOf (
          types.enum [
            "admin"
            "watcher"
          ]
        );
        default = { };
        example = {
          "09fa6a5996a213923b32f2fca58cf565de0f91cbaf3dad86542be8f56c8ca62e" = "admin";
        };
        description = "Endpoint IDs allowed on the admin ALPN with their role (`tunnelrs-ctl id` prints a ctl key's ID).";
      };
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the iroh UDP port. The http and tls listeners are meant for the edge and are never opened.";
      };
    };

    connector = {
      enable = mkEnableOption "the tunnelrs connector";
      package = mkOption {
        type = types.package;
        description = "The tunnelrs-connector package to use.";
      };
      keyFile = keyFileOption "tunnelrs-connector";
      server = serverAddrOptions;
      exposures = mkOption {
        default = { };
        example = {
          "app.example.com" = {
            backend = "127.0.0.1:8080";
            meta."k8s/auth" = "authentik";
          };
        };
        description = ''
          Exposures keyed by hostname. Changes are applied with a reload (SIGHUP) instead of a
          restart, so live sessions stay up.
        '';
        type = types.attrsOf (
          types.submodule {
            options = {
              backend = mkOption {
                type = types.str;
                example = "127.0.0.1:8080";
                description = "host:port of the backend the connector dials for this hostname.";
              };
              tls = mkOption {
                type = types.enum [
                  "terminate"
                  "passthrough"
                ];
                default = "terminate";
                description = "Where TLS ends: at the edge (terminate) or at the backend (passthrough).";
              };
              meta = mkOption {
                type = types.attrsOf types.str;
                default = { };
                description = "Opaque metadata passed to the k8s-operator.";
              };
            };
          }
        );
      };
    };
    useBinaryCache = mkEnableOption "trusting the luukblankenstijn.cachix.org binary cache system-wide, so tunnelrs is downloaded instead of built";
  };

  config = mkMerge [
    (mkIf config.services.tunnelrs.useBinaryCache {
      nix.settings = {
        substituters = [ "https://luukblankenstijn.cachix.org" ];
        trusted-public-keys = [
          "luukblankenstijn.cachix.org-1:gRz/ypm8zdDizcdAuWD6UKLVBDeObfHsNDWoAka2WSw="
        ];
      };
    })

    (mkIf serverCfg.enable {
      environment.systemPackages = [ serverCfg.ctlPackage ];

      systemd.services.tunnelrs-server = {
        description = "tunnelrs server";
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = hardening // {
          ExecStart = utils.escapeSystemdExecArgs [
            (lib.getExe serverCfg.package)
            "--config"
            serverConfigFile
          ];
          StateDirectory = "tunnelrs-server";
          StateDirectoryMode = "0700";
          LoadCredential = optional (serverCfg.keyFile != null) "key:${serverCfg.keyFile}";
        };
      };

      networking.firewall.allowedUDPPorts = mkIf (serverCfg.openFirewall && serverCfg.iroh.bind != null) [
        (portOf serverCfg.iroh.bind)
      ];
    })

    (mkIf connectorCfg.enable {
      environment.etc."tunnelrs/connector.toml".source =
        toml.generate "tunnelrs-connector.toml" connectorConfig;

      systemd.services.tunnelrs-connector = {
        description = "tunnelrs connector";
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];
        restartTriggers = [
          (builtins.toJSON {
            inherit (connectorConfig) key_path server;
            inherit (connectorCfg) keyFile;
          })
        ];
        reloadTriggers = [ (builtins.toJSON connectorConfig.expose) ];
        serviceConfig = hardening // {
          ExecStart = utils.escapeSystemdExecArgs [
            (lib.getExe connectorCfg.package)
            "--config"
            "/etc/tunnelrs/connector.toml"
          ];
          ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
          StateDirectory = "tunnelrs-connector";
          StateDirectoryMode = "0700";
          LoadCredential = optional (connectorCfg.keyFile != null) "key:${connectorCfg.keyFile}";
        };
      };
    })
  ];
}
