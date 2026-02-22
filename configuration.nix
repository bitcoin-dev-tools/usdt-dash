{
  pkgs,
  config,
  ...
}:
{
  imports = [ ./tracing/service.nix ];

  boot.loader.grub.enable = true;
  boot.loader.grub.device = "nodev";
  boot.loader.grub.efiSupport = true;
  boot.loader.grub.efiInstallAsRemovable = true;

  boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = 1;
  system.modulesTree = [ config.boot.kernelPackages.kernel.dev ];

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  networking.hostName = "usdt-dash";
  networking.useDHCP = false;
  networking.interfaces.enp1s0.ipv4.addresses = [
    {
      address = "188.245.67.250";
      prefixLength = 32;
    }
  ];
  networking.defaultGateway = {
    address = "172.31.1.1";
    interface = "enp1s0";
  };
  networking.nameservers = [
    "1.1.1.1"
    "1.0.0.1"
  ];
  networking.firewall.allowedTCPPorts = [
    443
    8333
  ];
  networking.firewall.allowedUDPPorts = [ 443 ];

  services.bitcoind.mainnet = {
    enable = true;
    prune = 2000;
    extraConfig = ''
      dbcache=1000
    '';
  };

  services.tor = {
    enable = true;
    client.enable = true;
  };

  services.prometheus = {
    enable = true;
    scrapeConfigs = [
      {
        job_name = "bitcoind";
        static_configs = [ { targets = [ "localhost:9435" ]; } ];
        scrape_interval = "5s";
      }
      {
        job_name = "node";
        static_configs = [ { targets = [ "localhost:9100" ]; } ];
        scrape_interval = "15s";
      }
    ];
  };

  services.prometheus.exporters.node = {
    enable = true;
    enabledCollectors = [
      "cpu"
      "diskstats"
      "filesystem"
      "loadavg"
      "meminfo"
      "netdev"
      "stat"
      "time"
      "vmstat"
    ];
  };

  services.grafana = {
    enable = true;
    settings = {
      server = {
        http_addr = "127.0.0.1";
        http_port = 3000;
        root_url = "https://tracing.fish.foo";
        serve_from_sub_path = false;
      };
      dashboards.default_home_dashboard_path = "/etc/grafana/dashboards/bitcoind.json";
      "auth.anonymous" = {
        enabled = true;
        org_role = "Viewer";
      };
      auth.disable_login_form = true;
      security.secret_key = "$__file{${config.sops.secrets.grafana-secret-key.path}}";
    };
    provision = {
      datasources.settings.datasources = [
        {
          name = "Prometheus";
          type = "prometheus";
          url = "http://localhost:9090";
          isDefault = true;
        }
      ];
      dashboards.settings.providers = [
        {
          name = "default";
          type = "file";
          options.path = "/etc/grafana/dashboards";
        }
      ];
    };
  };

  environment.etc."grafana/dashboards/bitcoind.json".source = ./grafana/dashboard.json;
  environment.etc."grafana/dashboards/node.json".source = ./grafana/node-dashboard.json;

  sops = {
    defaultSopsFile = ./secrets.yaml;
    age.sshKeyPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];
    secrets.caddy-cloudflare-token = { };
    secrets.grafana-secret-key = {
      owner = "grafana";
    };
    templates."caddy-env" = {
      content = "CF_API_TOKEN=${config.sops.placeholder."caddy-cloudflare-token"}";
    };
  };

  services.caddy = {
    enable = true;
    package = pkgs.caddy.withPlugins {
      plugins = [ "github.com/caddy-dns/cloudflare@v0.2.3" ];
      hash = "sha256-bJO2RIa6hYsoVl3y2L86EM34Dfkm2tlcEsXn2+COgzo=";
    };
    virtualHosts."tracing.fish.foo".extraConfig = ''
      tls {
        dns cloudflare {env.CF_API_TOKEN}
      }
      reverse_proxy localhost:3000
    '';
  };

  systemd.services.caddy.serviceConfig.EnvironmentFile = config.sops.templates."caddy-env".path;

  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "prohibit-password";

  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH988C5DbEPHfoCphoW23MWq9M6fmA4UTXREiZU0J7n0 will.hetzner@temp.com"
  ];

  environment.systemPackages = with pkgs; [
    neovim
    git
    htop
    curl
    bcc
    bpftrace
  ];

  time.timeZone = "UTC";
  system.stateVersion = "25.11";
}
