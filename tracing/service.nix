{
  config,
  pkgs,
  lib,
  ...
}:
let
  python = pkgs.python3.withPackages (ps: [
    ps.bcc
    ps.prometheus-client
  ]);
  script = ./bitcoind_exporter.py;
in
{
  systemd.services.bitcoind-tracing = {
    description = "Bitcoin Core USDT Tracing Exporter";
    after = [ "bitcoind-mainnet.service" ];
    bindsTo = [ "bitcoind-mainnet.service" ];
    wantedBy = [ "multi-user.target" ];

    path = [ pkgs.systemd ];

    serviceConfig = {
      Restart = "on-failure";
      RestartSec = 10;
    };

    script = ''
      PID=$(systemctl show --property MainPID --value bitcoind-mainnet.service)
      while [ "$PID" = "0" ]; do
        sleep 1
        PID=$(systemctl show --property MainPID --value bitcoind-mainnet.service)
      done
      exec ${python}/bin/python3 ${script} "$PID"
    '';
  };
}
