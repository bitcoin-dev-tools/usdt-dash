{
  config,
  pkgs,
  lib,
  ...
}:
let
  bpfPython = pkgs.python3.withPackages (ps: [
    ps.bcc
    ps.prometheus-client
  ]);
  rpcPython = pkgs.python3.withPackages (ps: [
    ps.prometheus-client
  ]);
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
      exec ${bpfPython}/bin/python3 ${./bitcoind_exporter.py} "$PID"
    '';
  };

  systemd.services.bitcoind-rpc-exporter = {
    description = "Bitcoin Core RPC Metrics Exporter";
    after = [ "bitcoind-mainnet.service" ];
    bindsTo = [ "bitcoind-mainnet.service" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      User = "bitcoind-mainnet";
      Group = "bitcoind-mainnet";
      Restart = "on-failure";
      RestartSec = 10;
    };

    script = ''
      exec ${rpcPython}/bin/python3 ${./rpc_exporter.py} /var/lib/bitcoind-mainnet/.cookie
    '';
  };
}
