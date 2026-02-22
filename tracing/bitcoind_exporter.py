#!/usr/bin/env python3
"""Bitcoin Core USDT tracepoint exporter for Prometheus.

Attaches BPF probes to bitcoind's 16 USDT tracepoints and exposes
the collected metrics in Prometheus exposition format on :9435.
"""

import ctypes as ct
import signal
import sys
import time

from bcc import BPF, USDT
from prometheus_client import Counter, Gauge, Summary, start_http_server

NETWORK_NAMES = {
    0: "unroutable",
    1: "ipv4",
    2: "ipv6",
    3: "onion",
    4: "i2p",
    5: "cjdns",
    6: "internal",
}

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

#define MAX_MSG_TYPE_LEN    13
#define MAX_REMOVAL_REASON  10

struct mempool_added_evt {
    s64 vsize;
    s64 fee;
};

struct mempool_removed_evt {
    char reason[MAX_REMOVAL_REASON];
};

struct net_msg_evt {
    char msg_type[MAX_MSG_TYPE_LEN];
    u64 size;
};

struct net_conn_evt {
    s32 network;
    u64 count;
};

struct net_closed_evt {
    s32 network;
};

struct block_connected_evt {
    s32 height;
    s64 tx_count;
    s64 inputs;
    s64 sigops;
    s64 duration_ns;
};

struct utxocache_flush_evt {
    s64 duration_us;
    u64 coins_count;
    u64 memory;
};

BPF_PERF_OUTPUT(mempool_added_events);
BPF_PERF_OUTPUT(mempool_removed_events);
BPF_PERF_OUTPUT(net_inbound_msg_events);
BPF_PERF_OUTPUT(net_outbound_msg_events);
BPF_PERF_OUTPUT(net_inbound_conn_events);
BPF_PERF_OUTPUT(net_outbound_conn_events);
BPF_PERF_OUTPUT(net_closed_conn_events);
BPF_PERF_OUTPUT(block_connected_events);
BPF_PERF_OUTPUT(utxocache_flush_events);

BPF_ARRAY(replaced_count, u64, 1);
BPF_ARRAY(rejected_count, u64, 1);
BPF_ARRAY(evicted_count, u64, 1);
BPF_ARRAY(misbehaving_count, u64, 1);
BPF_ARRAY(utxo_add_cnt, u64, 1);
BPF_ARRAY(utxo_spent_cnt, u64, 1);
BPF_ARRAY(utxo_uncache_cnt, u64, 1);

// mempool:added — hash*, vsize, fee
int trace_mempool_added(struct pt_regs *ctx) {
    struct mempool_added_evt evt = {};
    bpf_usdt_readarg(2, ctx, &evt.vsize);
    bpf_usdt_readarg(3, ctx, &evt.fee);
    mempool_added_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// mempool:removed — hash*, reason*, vsize, fee, entry_time
int trace_mempool_removed(struct pt_regs *ctx) {
    struct mempool_removed_evt evt = {};
    void *p = NULL;
    bpf_usdt_readarg(2, ctx, &p);
    bpf_probe_read_user_str(&evt.reason, sizeof(evt.reason), p);
    mempool_removed_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// mempool:replaced — count only
int trace_mempool_replaced(struct pt_regs *ctx) {
    int zero = 0;
    u64 *val = replaced_count.lookup(&zero);
    if (val) lock_xadd(val, 1);
    return 0;
}

// mempool:rejected — count only
int trace_mempool_rejected(struct pt_regs *ctx) {
    int zero = 0;
    u64 *val = rejected_count.lookup(&zero);
    if (val) lock_xadd(val, 1);
    return 0;
}

// net:inbound_message — id, addr*, conn_type*, msg_type*, size, data*
int trace_net_inbound_msg(struct pt_regs *ctx) {
    struct net_msg_evt evt = {};
    void *p = NULL;
    bpf_usdt_readarg(4, ctx, &p);
    bpf_probe_read_user_str(&evt.msg_type, sizeof(evt.msg_type), p);
    bpf_usdt_readarg(5, ctx, &evt.size);
    net_inbound_msg_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// net:outbound_message — id, addr*, conn_type*, msg_type*, size, data*
int trace_net_outbound_msg(struct pt_regs *ctx) {
    struct net_msg_evt evt = {};
    void *p = NULL;
    bpf_usdt_readarg(4, ctx, &p);
    bpf_probe_read_user_str(&evt.msg_type, sizeof(evt.msg_type), p);
    bpf_usdt_readarg(5, ctx, &evt.size);
    net_outbound_msg_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// net:inbound_connection — id, addr*, conn_type*, network, count
int trace_net_inbound_conn(struct pt_regs *ctx) {
    struct net_conn_evt evt = {};
    bpf_usdt_readarg(4, ctx, &evt.network);
    bpf_usdt_readarg(5, ctx, &evt.count);
    net_inbound_conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// net:outbound_connection — id, addr*, conn_type*, network, count
int trace_net_outbound_conn(struct pt_regs *ctx) {
    struct net_conn_evt evt = {};
    bpf_usdt_readarg(4, ctx, &evt.network);
    bpf_usdt_readarg(5, ctx, &evt.count);
    net_outbound_conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// net:closed_connection — id, addr*, conn_type*, network, duration
int trace_net_closed_conn(struct pt_regs *ctx) {
    struct net_closed_evt evt = {};
    bpf_usdt_readarg(4, ctx, &evt.network);
    net_closed_conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// net:evicted_inbound_connection — count only
int trace_net_evicted(struct pt_regs *ctx) {
    int zero = 0;
    u64 *val = evicted_count.lookup(&zero);
    if (val) lock_xadd(val, 1);
    return 0;
}

// net:misbehaving_connection — count only
int trace_net_misbehaving(struct pt_regs *ctx) {
    int zero = 0;
    u64 *val = misbehaving_count.lookup(&zero);
    if (val) lock_xadd(val, 1);
    return 0;
}

// validation:block_connected — hash*, height, tx_count, inputs, sigops, duration_ns
int trace_block_connected(struct pt_regs *ctx) {
    struct block_connected_evt evt = {};
    bpf_usdt_readarg(2, ctx, &evt.height);
    bpf_usdt_readarg(3, ctx, &evt.tx_count);
    bpf_usdt_readarg(4, ctx, &evt.inputs);
    bpf_usdt_readarg(5, ctx, &evt.sigops);
    bpf_usdt_readarg(6, ctx, &evt.duration_ns);
    block_connected_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// utxocache:flush — duration_us, mode, coins_count, memory, for_prune
int trace_utxocache_flush(struct pt_regs *ctx) {
    struct utxocache_flush_evt evt = {};
    bpf_usdt_readarg(1, ctx, &evt.duration_us);
    bpf_usdt_readarg(3, ctx, &evt.coins_count);
    bpf_usdt_readarg(4, ctx, &evt.memory);
    utxocache_flush_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// utxocache:add — hash*, index, height, value, is_coinbase
int trace_utxocache_add(struct pt_regs *ctx) {
    int zero = 0;
    u64 *cnt = utxo_add_cnt.lookup(&zero);
    if (cnt) lock_xadd(cnt, 1);
    return 0;
}

// utxocache:spent — hash*, index, height, value, is_coinbase
int trace_utxocache_spent(struct pt_regs *ctx) {
    int zero = 0;
    u64 *cnt = utxo_spent_cnt.lookup(&zero);
    if (cnt) lock_xadd(cnt, 1);
    return 0;
}

// utxocache:uncache — count only
int trace_utxocache_uncache(struct pt_regs *ctx) {
    int zero = 0;
    u64 *val = utxo_uncache_cnt.lookup(&zero);
    if (val) lock_xadd(val, 1);
    return 0;
}
"""

MEMPOOL_ADDED = Counter("bitcoind_mempool_added_total", "Transactions added to mempool")
MEMPOOL_ADDED_FEES = Counter(
    "bitcoind_mempool_added_fees_satoshis_total", "Total fees of added transactions in satoshis"
)
MEMPOOL_ADDED_VBYTES = Counter(
    "bitcoind_mempool_added_vbytes_total", "Total vbytes of added transactions"
)
MEMPOOL_REMOVED = Counter(
    "bitcoind_mempool_removed_total", "Transactions removed from mempool", ["reason"]
)
MEMPOOL_REPLACED = Counter("bitcoind_mempool_replaced_total", "Transactions replaced in mempool")
MEMPOOL_REJECTED = Counter("bitcoind_mempool_rejected_total", "Transactions rejected from mempool")

P2P_MESSAGES = Counter("bitcoind_p2p_messages_total", "P2P messages", ["direction", "msg_type"])
P2P_BYTES = Counter("bitcoind_p2p_bytes_total", "P2P message bytes", ["direction", "msg_type"])

CONN_INBOUND = Gauge("bitcoind_connections_inbound", "Current inbound connections")
CONN_OUTBOUND = Gauge("bitcoind_connections_outbound", "Current outbound connections")
CONN_OPENED = Counter(
    "bitcoind_connections_opened_total", "Connections opened", ["direction", "network"]
)
CONN_CLOSED = Counter("bitcoind_connections_closed_total", "Connections closed", ["network"])
CONN_EVICTED = Counter("bitcoind_connections_evicted_total", "Inbound connections evicted")
CONN_MISBEHAVING = Counter("bitcoind_connections_misbehaving_total", "Misbehaving connections")

BLOCK_HEIGHT = Gauge("bitcoind_block_height", "Latest connected block height")
BLOCK_CONNECTED_SECS = Gauge("bitcoind_block_connected_seconds", "Last block connection duration")
BLOCK_TXS = Gauge("bitcoind_block_transactions", "Transactions in last connected block")
BLOCK_SIGOPS = Gauge("bitcoind_block_sigops", "Sigops in last connected block")
BLOCK_INPUTS = Gauge("bitcoind_block_inputs", "Inputs in last connected block")

UTXO_FLUSH_DURATION = Summary(
    "bitcoind_utxocache_flush_duration_seconds", "UTXO cache flush duration"
)
UTXO_FLUSH_COINS = Gauge("bitcoind_utxocache_flush_coins", "Coins in last UTXO cache flush")
UTXO_FLUSH_MEMORY = Gauge(
    "bitcoind_utxocache_flush_memory_bytes", "Memory usage of last UTXO cache flush"
)
UTXO_ADDED = Counter("bitcoind_utxocache_coins_added_total", "Coins added to UTXO cache")
UTXO_SPENT = Counter("bitcoind_utxocache_coins_spent_total", "Coins spent from UTXO cache")
UTXO_UNCACHED = Counter("bitcoind_utxocache_coins_uncached_total", "Coins uncached from UTXO cache")


def network_name(n):
    return NETWORK_NAMES.get(n, f"unknown_{n}")


PROBES = [
    ("mempool:added", "trace_mempool_added"),
    ("mempool:removed", "trace_mempool_removed"),
    ("mempool:replaced", "trace_mempool_replaced"),
    ("mempool:rejected", "trace_mempool_rejected"),
    ("net:inbound_message", "trace_net_inbound_msg"),
    ("net:outbound_message", "trace_net_outbound_msg"),
    ("net:inbound_connection", "trace_net_inbound_conn"),
    ("net:outbound_connection", "trace_net_outbound_conn"),
    ("net:closed_connection", "trace_net_closed_conn"),
    ("net:evicted_inbound_connection", "trace_net_evicted"),
    ("net:misbehaving_connection", "trace_net_misbehaving"),
    ("validation:block_connected", "trace_block_connected"),
    ("utxocache:flush", "trace_utxocache_flush"),
    ("utxocache:add", "trace_utxocache_add"),
    ("utxocache:spent", "trace_utxocache_spent"),
    ("utxocache:uncache", "trace_utxocache_uncache"),
]

MAP_COUNTERS = {
    "replaced_count": MEMPOOL_REPLACED,
    "rejected_count": MEMPOOL_REJECTED,
    "evicted_count": CONN_EVICTED,
    "misbehaving_count": CONN_MISBEHAVING,
    "utxo_add_cnt": UTXO_ADDED,
    "utxo_spent_cnt": UTXO_SPENT,
    "utxo_uncache_cnt": UTXO_UNCACHED,
}


def main(pid, port=9435):
    usdt = USDT(pid=pid)
    for probe, fn in PROBES:
        usdt.enable_probe(probe=probe, fn_name=fn)

    bpf = BPF(text=BPF_PROGRAM, usdt_contexts=[usdt])

    def handle_mempool_added(cpu, data, size):
        evt = bpf["mempool_added_events"].event(data)
        MEMPOOL_ADDED.inc()
        MEMPOOL_ADDED_FEES.inc(evt.fee)
        MEMPOOL_ADDED_VBYTES.inc(evt.vsize)

    def handle_mempool_removed(cpu, data, size):
        evt = bpf["mempool_removed_events"].event(data)
        reason = evt.reason.decode("utf-8", errors="replace")
        MEMPOOL_REMOVED.labels(reason=reason).inc()

    def handle_net_inbound_msg(cpu, data, size):
        evt = bpf["net_inbound_msg_events"].event(data)
        msg_type = evt.msg_type.decode("utf-8", errors="replace")
        P2P_MESSAGES.labels(direction="inbound", msg_type=msg_type).inc()
        P2P_BYTES.labels(direction="inbound", msg_type=msg_type).inc(evt.size)

    def handle_net_outbound_msg(cpu, data, size):
        evt = bpf["net_outbound_msg_events"].event(data)
        msg_type = evt.msg_type.decode("utf-8", errors="replace")
        P2P_MESSAGES.labels(direction="outbound", msg_type=msg_type).inc()
        P2P_BYTES.labels(direction="outbound", msg_type=msg_type).inc(evt.size)

    def handle_net_inbound_conn(cpu, data, size):
        evt = bpf["net_inbound_conn_events"].event(data)
        CONN_INBOUND.set(evt.count)
        CONN_OPENED.labels(direction="inbound", network=network_name(evt.network)).inc()

    def handle_net_outbound_conn(cpu, data, size):
        evt = bpf["net_outbound_conn_events"].event(data)
        CONN_OUTBOUND.set(evt.count)
        CONN_OPENED.labels(direction="outbound", network=network_name(evt.network)).inc()

    def handle_net_closed_conn(cpu, data, size):
        evt = bpf["net_closed_conn_events"].event(data)
        CONN_CLOSED.labels(network=network_name(evt.network)).inc()

    def handle_block_connected(cpu, data, size):
        evt = bpf["block_connected_events"].event(data)
        BLOCK_HEIGHT.set(evt.height)
        BLOCK_CONNECTED_SECS.set(evt.duration_ns / 1e9)
        BLOCK_TXS.set(evt.tx_count)
        BLOCK_SIGOPS.set(evt.sigops)
        BLOCK_INPUTS.set(evt.inputs)

    def handle_utxocache_flush(cpu, data, size):
        evt = bpf["utxocache_flush_events"].event(data)
        UTXO_FLUSH_DURATION.observe(evt.duration_us / 1e6)
        UTXO_FLUSH_COINS.set(evt.coins_count)
        UTXO_FLUSH_MEMORY.set(evt.memory)

    bpf["mempool_added_events"].open_perf_buffer(handle_mempool_added, page_cnt=16)
    bpf["mempool_removed_events"].open_perf_buffer(handle_mempool_removed, page_cnt=32)
    bpf["net_inbound_msg_events"].open_perf_buffer(handle_net_inbound_msg, page_cnt=64)
    bpf["net_outbound_msg_events"].open_perf_buffer(handle_net_outbound_msg, page_cnt=64)
    bpf["net_inbound_conn_events"].open_perf_buffer(handle_net_inbound_conn)
    bpf["net_outbound_conn_events"].open_perf_buffer(handle_net_outbound_conn)
    bpf["net_closed_conn_events"].open_perf_buffer(handle_net_closed_conn)
    bpf["block_connected_events"].open_perf_buffer(handle_block_connected)
    bpf["utxocache_flush_events"].open_perf_buffer(handle_utxocache_flush)

    prev = {name: 0 for name in MAP_COUNTERS}

    def sync_map_counters():
        for map_name, metric in MAP_COUNTERS.items():
            current = bpf[map_name][ct.c_int(0)].value
            delta = current - prev[map_name]
            if delta > 0:
                prev[map_name] = current
                metric.inc(delta)

    start_http_server(port)
    print(f"Listening on :{port}, tracing bitcoind pid {pid}")

    running = True

    def stop(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while running:
        bpf.perf_buffer_poll(timeout=100)
        sync_map_counters()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bitcoind-pid> [port]", file=sys.stderr)
        sys.exit(1)
    main(int(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 9435)
