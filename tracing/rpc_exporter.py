#!/usr/bin/env python3
"""Bitcoin Core RPC metrics exporter for Prometheus.

Polls bitcoind's JSON-RPC interface and exposes chain, mempool,
and network state as Prometheus metrics on :9436.
"""

import base64
import json
import signal
import sys
import time
import urllib.error
import urllib.request

from prometheus_client import Gauge, start_http_server

CHAIN_BLOCKS = Gauge("bitcoind_blockchain_blocks", "Current block count")
CHAIN_HEADERS = Gauge("bitcoind_blockchain_headers", "Current header count")
CHAIN_SYNC_PROGRESS = Gauge(
    "bitcoind_blockchain_verification_progress", "Chain verification progress"
)
CHAIN_DIFFICULTY = Gauge("bitcoind_blockchain_difficulty", "Current difficulty")
CHAIN_SIZE_ON_DISK = Gauge("bitcoind_blockchain_size_bytes", "Estimated blockchain size on disk")

MEMPOOL_TX_COUNT = Gauge("bitcoind_mempool_size", "Transactions in mempool")
MEMPOOL_BYTES = Gauge("bitcoind_mempool_bytes", "Mempool size in vbytes")
MEMPOOL_USAGE = Gauge("bitcoind_mempool_usage_bytes", "Mempool memory usage")
MEMPOOL_MAX = Gauge("bitcoind_mempool_max_bytes", "Maximum mempool size")
MEMPOOL_MIN_FEE = Gauge(
    "bitcoind_mempool_minfee_per_kb", "Minimum fee rate for mempool acceptance (BTC/kB)"
)

NET_BYTES_RECV = Gauge("bitcoind_net_bytes_recv_total", "Total bytes received")
NET_BYTES_SENT = Gauge("bitcoind_net_bytes_sent_total", "Total bytes sent")
NET_CONNECTIONS_IN = Gauge("bitcoind_net_connections_in", "Inbound connections")
NET_CONNECTIONS_OUT = Gauge("bitcoind_net_connections_out", "Outbound connections")


def rpc_call(url, auth, method):
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": []}
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["result"]


def read_cookie(path):
    with open(path) as f:
        return base64.b64encode(f.read().strip().encode()).decode()


def poll(url, cookie_path):
    auth = read_cookie(cookie_path)

    info = rpc_call(url, auth, "getblockchaininfo")
    CHAIN_BLOCKS.set(info["blocks"])
    CHAIN_HEADERS.set(info["headers"])
    CHAIN_SYNC_PROGRESS.set(info["verificationprogress"])
    CHAIN_DIFFICULTY.set(info["difficulty"])
    CHAIN_SIZE_ON_DISK.set(info.get("size_on_disk", 0))

    mempool = rpc_call(url, auth, "getmempoolinfo")
    MEMPOOL_TX_COUNT.set(mempool["size"])
    MEMPOOL_BYTES.set(mempool["bytes"])
    MEMPOOL_USAGE.set(mempool["usage"])
    MEMPOOL_MAX.set(mempool["maxmempool"])
    MEMPOOL_MIN_FEE.set(mempool["mempoolminfee"])

    nettotals = rpc_call(url, auth, "getnettotals")
    NET_BYTES_RECV.set(nettotals["totalbytesrecv"])
    NET_BYTES_SENT.set(nettotals["totalbytessent"])

    netinfo = rpc_call(url, auth, "getnetworkinfo")
    NET_CONNECTIONS_IN.set(netinfo.get("connections_in", 0))
    NET_CONNECTIONS_OUT.set(netinfo.get("connections_out", 0))


def main(cookie_path, port=9436, rpc_port=8332, interval=15):
    url = f"http://127.0.0.1:{rpc_port}"
    start_http_server(port)
    print(f"Listening on :{port}, polling bitcoind RPC at :{rpc_port}")

    running = True

    def stop(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while running:
        try:
            poll(url, cookie_path)
        except Exception as e:
            print(f"RPC poll failed: {e}", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cookie-path> [port] [rpc-port]", file=sys.stderr)
        sys.exit(1)
    main(
        sys.argv[1],
        int(sys.argv[2]) if len(sys.argv) > 2 else 9436,
        int(sys.argv[3]) if len(sys.argv) > 3 else 8332,
    )
