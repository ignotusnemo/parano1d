#!/usr/bin/env python3
"""Clean release-binary sync suite: exact catch-up and deep snapshot recovery.

Every run starts from empty primary and secondary data directories. Ordinary
catch-up uses an exact suffix until a deterministic finalized snapshot boundary
exists ahead of the requester, then switches to that snapshot. This closes the
six-block boundary-alignment gap without changing 18-block finality.
"""

import datetime
import hashlib
import json
import math
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NODE_BIN = ROOT / "target" / "release" / "parano1d"
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_SYNC_DIR", str(RUN_PARENT / f"sync-clean-{STAMP}")
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_SYNC_BASE_PORT", "20300"))
PRIMARY_P2P = BASE_PORT
PRIMARY_RPC = BASE_PORT + 1
SECONDARY_P2P = BASE_PORT + 10
SECONDARY_RPC = BASE_PORT + 11


class LiveSyncError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise LiveSyncError(message)


def rpc(port, method, params=None, timeout=10):
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method if method.startswith("paranoid_") else f"paranoid_{method}",
            "params": params or [],
        }
    ).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=payload,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read())
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise LiveSyncError(f"RPC {method} transport failed: {error}") from error
    if result.get("error") is not None:
        raise LiveSyncError(f"RPC {method} failed: {result['error']}")
    return result.get("result")


def port_is_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def int_field(line, field):
    match = re.search(rf"(?:^|\s){re.escape(field)}=(\d+)(?:\s|$)", line)
    return int(match.group(1)) if match else None


class Node:
    def __init__(self, name, p2p_port, rpc_port):
        self.name = name
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.root = BASE / name
        self.data_dir = self.root / "data"
        self.config = self.root / "parano1d.toml"
        self.proc = None
        self.log_handle = None
        self.log_path = None

    @property
    def seed(self):
        return f"127.0.0.1:{self.p2p_port}"

    def start(self, label, mode="node", genesis=False, seeds=None):
        require(self.proc is None or self.proc.poll() is not None, f"{self.name} already runs")
        self.root.mkdir(parents=True, exist_ok=True)
        self.log_path = BASE / "logs" / f"{label}.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        args = [
            str(NODE_BIN),
            "--mode",
            mode,
            "--config",
            str(self.config),
            "--data-dir",
            str(self.data_dir),
            "--p2p-listen",
            f"127.0.0.1:{self.p2p_port}",
            "--rpc-listen",
            f"127.0.0.1:{self.rpc_port}",
            "--disable-dns-seeds",
            "--log",
            "debug",
        ]
        if genesis:
            args.append("--genesis")
        for seed in seeds or []:
            args.extend(["--seed", seed])
        self.log_handle = open(self.log_path, "wb", buffering=0)
        started = time.monotonic()
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_handle, stderr=subprocess.STDOUT
        )
        print(
            f"[start] {label} pid={self.proc.pid} mode={mode} genesis={genesis}",
            flush=True,
        )
        deadline = time.monotonic() + 300
        last = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise LiveSyncError(
                    f"{label} exited during startup with {self.proc.returncode}"
                )
            try:
                last = self.info(timeout=3)
                elapsed = time.monotonic() - started
                print(
                    f"[ready] {label} height={last['height']} startup={elapsed:.3f}s",
                    flush=True,
                )
                return last, elapsed
            except LiveSyncError:
                time.sleep(0.5)
        raise LiveSyncError(f"{label} RPC startup timeout; last={last}")

    def stop(self):
        if self.proc is None or self.proc.poll() is not None:
            self._close_log()
            return
        try:
            rpc(self.rpc_port, "stop", timeout=5)
        except LiveSyncError as error:
            print(f"[stop] {self.name}: {error}", flush=True)
        try:
            self.proc.wait(timeout=45)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        print(f"[stopped] {self.name} code={self.proc.returncode}", flush=True)
        self._close_log()

    def _close_log(self):
        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None

    def info(self, timeout=10):
        return rpc(self.rpc_port, "getChainInfo", timeout=timeout)

    def height(self):
        return int(self.info()["height"])

    def log_text(self):
        require(self.log_path is not None, f"{self.name} has no active log")
        assert self.log_path is not None
        return self.log_path.read_text(errors="replace")


def wait_exact_mining_height(node, target, timeout):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        height = node.height()
        if height != last:
            print(f"[mine] {node.name} height={height}/{target}", flush=True)
            last = height
        if height == target:
            return height
        if height > target:
            raise LiveSyncError(f"miner overshot exact target {target}: height={height}")
        time.sleep(0.2)
    raise LiveSyncError(f"miner did not reach exact height {target}; last={last}")


def exact_tip(primary, secondary):
    left = primary.info()
    right = secondary.info()
    return (
        int(left["height"]) == int(right["height"])
        and left["best_hash"] == right["best_hash"]
    )


def wait_converged(primary, secondary, timeout):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        left = primary.info()
        right = secondary.info()
        state = (int(left["height"]), int(right["height"]))
        if state != last:
            print(f"[sync] primary={state[0]} secondary={state[1]}", flush=True)
            last = state
        if state[0] == state[1] and left["best_hash"] == right["best_hash"]:
            return left
        time.sleep(0.5)
    raise LiveSyncError(f"tip convergence timeout; last={last}")


def compare_hashes(primary, secondary, start, end):
    for height in range(start, end + 1):
        left = rpc(primary.rpc_port, "getBlockHash", [height])
        right = rpc(secondary.rpc_port, "getBlockHash", [height])
        require(left is not None, f"primary missing block hash h={height}")
        require(left == right, f"canonical hash mismatch h={height}: {left} != {right}")
    print(f"[hashes] exact match h={start}..{end}", flush=True)


def sync_counts(text):
    return {
        "snapshot_installs": text.count("snapshot install completed"),
        "snapshot_boundaries": [
            int(value)
            for value in re.findall(
                r"snapshot boundary State installed[^\n]* snapshot_height=(\d+)",
                text,
            )
        ],
        "history_step_verifications": text.count(
            'phase="history_step_terminal"'
        ),
        "applied_p2p_blocks": text.count("applied P2P block"),
        "compact_suffixes": text.count(
            "compact recent suffix application completed"
        ),
        "compact_suffix_blocks": [
            int(value)
            for value in re.findall(
                r"compact recent suffix application completed[^\n]* blocks=(\d+)",
                text,
            )
        ],
        "exact_suffixes": text.count(
            "header-first exact suffix application completed"
        ),
        "exact_suffix_blocks": [
            int(value)
            for value in re.findall(
                r"header-first exact suffix application completed[^\n]* blocks=(\d+)",
                text,
            )
        ],
        "exact_suffix_terminal_verifications": text.count(
            "exact suffix terminal verified outside the chain writer"
        ),
        "manifest_requests": text.count("requesting state manifest"),
        "suffix_measurements": [
            int(value)
            for value in re.findall(
                r'phase="retained_suffix_apply"[^\n]* count=(\d+)', text
            )
        ],
        "post_snapshot_suffix_requests": text.count(
            "requested fresh retained suffix after snapshot install"
        ),
    }


def wait_sync_counts(node, predicate, timeout=30):
    """Wait until completion telemetry catches up with the committed RPC tip."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = sync_counts(node.log_text())
        if predicate(last):
            return last
        time.sleep(0.1)
    raise LiveSyncError(f"sync completion telemetry timeout; last={last}")


SYNC_FAILURES = (
    "HistoryStep terminal request failed",
    "HistoryStep terminal response failed",
    "snapshot rejected",
    "snapshot install failed",
    "P2P block rejected",
    "block sync request failed",
    "unknown or delayed retained-block response",
    "stale recent gap",
    "ERROR",
)


def assert_no_sync_failures(label, text):
    failures = [line for line in text.splitlines() if any(token in line for token in SYNC_FAILURES)]
    require(not failures, f"{label} contains sync failures: {failures[-5:]}")


def mining_summary(text):
    accepted = []
    for line in text.splitlines():
        if "block accepted" not in line:
            continue
        accepted.append(
            {
                "height": int_field(line, "height"),
                "history_step_ms": int_field(line, "history_step_ms"),
                "pow_ms": int_field(line, "pow_ms"),
                "nonce_to_commit_ms": int_field(line, "nonce_to_commit_ms"),
            }
        )
    history = [item["history_step_ms"] for item in accepted if item["history_step_ms"] is not None]
    pow_times = [item["pow_ms"] for item in accepted if item["pow_ms"] is not None]
    return {
        "accepted_blocks": len(accepted),
        "history_step_ms_p50": percentile(history, 0.50),
        "history_step_ms_p95": percentile(history, 0.95),
        "pow_ms_p50": percentile(pow_times, 0.50),
        "pow_ms_p95": percentile(pow_times, 0.95),
    }


def mine_phase(primary, label, start_height, count, genesis):
    target = start_height + count
    _, startup = primary.start(label, mode="miner", genesis=genesis)
    wait_exact_mining_height(primary, target, timeout=max(900, count * 45))
    primary.stop()
    text = primary.log_text()
    assert_no_sync_failures(label, text)
    summary = {
        "from_height": start_height,
        "to_height": target,
        "count": count,
        "startup_s": round(startup, 3),
        **mining_summary(text),
    }
    require(
        summary["accepted_blocks"] == count,
        f"{label} accepted {summary['accepted_blocks']} blocks, expected {count}",
    )
    print(f"[mining-summary] {label}: {summary}", flush=True)
    return summary


def main():
    require(NODE_BIN.is_file(), f"release node is missing: {NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    for port in (PRIMARY_P2P, PRIMARY_RPC, SECONDARY_P2P, SECONDARY_RPC):
        require(port_is_free(port), f"port is occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_SYNC_RUN").write_text(str(BASE) + "\n")
    print(f"[run] {BASE}", flush=True)
    print(f"[binary] sha256={sha256(NODE_BIN)} size={NODE_BIN.stat().st_size}", flush=True)

    primary = Node("primary", PRIMARY_P2P, PRIMARY_RPC)
    short_secondary = Node("secondary-short", SECONDARY_P2P, SECONDARY_RPC)
    secondary = Node("secondary", SECONDARY_P2P, SECONDARY_RPC)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": sha256(NODE_BIN),
        "binary_size": NODE_BIN.stat().st_size,
        "phases": {},
        "status": "running",
    }
    error = None
    try:
        # First prove that a fresh node discovers a short, already-idle chain.
        # Its finalized snapshot manifest is empty, so this must use the
        # anchored-header/compact-suffix path rather than waiting for gossip.
        summary["phases"]["genesis_to_short_tip_mining"] = mine_phase(
            primary, "01-primary-genesis-to-h5-mining", 0, 5, genesis=True
        )
        info, startup = primary.start("02-primary-h5-source")
        require(int(info["height"]) == 5, f"short source height is {info['height']}, expected 5")
        started = time.monotonic()
        short_secondary.start("03-secondary-fresh-h5", seeds=[primary.seed])
        wait_converged(primary, short_secondary, timeout=300)
        elapsed = time.monotonic() - started
        fresh_short = wait_sync_counts(
            short_secondary,
            lambda counts: counts["exact_suffix_blocks"] == [5],
        )
        assert_no_sync_failures("fresh-h5", short_secondary.log_text())
        require(fresh_short["snapshot_installs"] == 0, f"fresh h5 used snapshot: {fresh_short}")
        require(
            fresh_short["exact_suffix_blocks"] == [5],
            f"fresh h5 exact suffix is not exactly five blocks: {fresh_short}",
        )
        require(
            fresh_short["exact_suffix_terminal_verifications"] == 1,
            f"fresh h5 did not verify exactly one terminal: {fresh_short}",
        )
        require(
            fresh_short["applied_p2p_blocks"] == 0,
            f"fresh h5 unexpectedly downloaded per-block terminals: {fresh_short}",
        )
        compare_hashes(primary, short_secondary, 0, 5)
        summary["phases"]["fresh_short_exact_sync"] = {
            "source_height": 5,
            "source_startup_s": round(startup, 3),
            "elapsed_s": round(elapsed, 3),
            **fresh_short,
        }
        short_secondary.stop()
        primary.stop()

        # At h19 no positive six-block snapshot boundary exists yet. A fresh
        # node must therefore use one exact suffix rather than loop forever on
        # an empty manifest.
        summary["phases"]["short_tip_to_snapshot_tip_mining"] = mine_phase(
            primary, "04-primary-h5-to-h19-mining", 5, 14, genesis=True
        )
        info, startup = primary.start("05-primary-fresh-source")
        require(int(info["height"]) == 19, f"primary restart height is {info['height']}, expected 19")
        require(
            rpc(primary.rpc_port, "getHistoryStepTerminal") is not None,
            "height-19 source has no finalized HistoryStep terminal",
        )

        started = time.monotonic()
        secondary.start("06-secondary-fresh", seeds=[primary.seed])
        wait_converged(primary, secondary, timeout=600)
        elapsed = time.monotonic() - started
        fresh = wait_sync_counts(
            secondary,
            lambda counts: counts["exact_suffix_blocks"] == [19],
        )
        assert_no_sync_failures("fresh", secondary.log_text())
        require(fresh["snapshot_installs"] == 0, f"fresh h19 used snapshot: {fresh}")
        require(
            fresh["exact_suffix_blocks"] == [19],
            f"fresh h19 exact suffix is not exactly 19 blocks: {fresh}",
        )
        require(
            fresh["exact_suffix_terminal_verifications"] == 1,
            f"fresh h19 did not verify exactly one terminal: {fresh}",
        )
        require(fresh["applied_p2p_blocks"] == 0, f"fresh h19 used legacy blocks: {fresh}")
        compare_hashes(primary, secondary, 0, 19)
        summary["phases"]["fresh_pre_boundary_exact_sync"] = {
            "source_height": 19,
            "source_startup_s": round(startup, 3),
            "elapsed_s": round(elapsed, 3),
            **fresh,
        }

        secondary.stop()
        primary.stop()
        summary["phases"]["gap5_mining"] = mine_phase(
            primary, "07-primary-gap5-mining", 19, 5, genesis=True
        )
        info, startup = primary.start("08-primary-gap5-source")
        require(int(info["height"]) == 24, f"gap5 source height is {info['height']}, expected 24")
        started = time.monotonic()
        secondary.start("09-secondary-gap5", seeds=[primary.seed])
        wait_converged(primary, secondary, timeout=300)
        elapsed = time.monotonic() - started
        gap5 = wait_sync_counts(
            secondary,
            lambda counts: counts["exact_suffix_blocks"] == [5],
        )
        assert_no_sync_failures("gap5", secondary.log_text())
        require(gap5["snapshot_installs"] == 0, f"gap5 unexpectedly used snapshot: {gap5}")
        require(
            gap5["exact_suffix_blocks"] == [5],
            f"gap5 exact suffix is not exactly five blocks: {gap5}",
        )
        require(
            gap5["exact_suffix_terminal_verifications"] == 1,
            f"gap5 did not verify exactly one terminal: {gap5}",
        )
        require(
            gap5["applied_p2p_blocks"] == 0,
            f"gap5 unexpectedly downloaded per-block terminals: {gap5}",
        )
        compare_hashes(primary, secondary, 0, 24)
        summary["phases"]["gap5_exact_sync"] = {
            "from_height": 19,
            "to_height": 24,
            "gap": 5,
            "source_startup_s": round(startup, 3),
            "elapsed_s": round(elapsed, 3),
            **gap5,
        }

        secondary.stop()
        primary.stop()
        # At h43 the newest rounded finalized snapshot boundary is h24, equal
        # to this node's current tip. There is no newer State generation to
        # install, so routing must choose the available 19-block exact suffix
        # rather than loop on h24.
        summary["phases"]["gap19_mining"] = mine_phase(
            primary, "10-primary-gap19-mining", 24, 19, genesis=True
        )
        info, startup = primary.start("11-primary-gap19-source")
        require(int(info["height"]) == 43, f"gap19 source height is {info['height']}, expected 43")
        started = time.monotonic()
        secondary.start("12-secondary-gap19", seeds=[primary.seed])
        wait_converged(primary, secondary, timeout=600)
        elapsed = time.monotonic() - started
        gap19 = wait_sync_counts(
            secondary,
            lambda counts: counts["exact_suffix_blocks"] == [19],
        )
        assert_no_sync_failures("gap19", secondary.log_text())
        require(gap19["snapshot_installs"] == 0, f"gap19 unexpectedly used snapshot: {gap19}")
        require(
            gap19["exact_suffix_blocks"] == [19],
            f"gap19 exact suffix is not exactly 19 blocks: {gap19}",
        )
        require(
            gap19["exact_suffix_terminal_verifications"] == 1,
            f"gap19 did not verify exactly one terminal: {gap19}",
        )
        require(gap19["applied_p2p_blocks"] == 0, f"gap19 used legacy blocks: {gap19}")
        compare_hashes(primary, secondary, 0, 43)
        summary["phases"]["gap19_exact_sync"] = {
            "from_height": 24,
            "to_height": 43,
            "gap": 19,
            "source_startup_s": round(startup, 3),
            "elapsed_s": round(elapsed, 3),
            **gap19,
        }

        # A node left at h5 now falls 43 blocks behind. The h30 snapshot is
        # ahead of its local State, so normal deep sync must install it once
        # and then finish the authenticated 18-block tail to h48.
        secondary.stop()
        primary.stop()
        summary["phases"]["deep_gap_mining"] = mine_phase(
            primary, "13-primary-h43-to-h48-mining", 43, 5, genesis=True
        )
        info, startup = primary.start("14-primary-h48-source")
        require(int(info["height"]) == 48, f"deep source height is {info['height']}, expected 48")
        started = time.monotonic()
        short_secondary.start("15-secondary-h5-deep-gap", seeds=[primary.seed])
        wait_converged(primary, short_secondary, timeout=600)
        elapsed = time.monotonic() - started
        # The chain commit becomes visible through RPC immediately before the
        # completion event is formatted. On a fast 18-block atomic suffix this
        # gap is observable, so do not classify a successful commit from a
        # transiently incomplete log snapshot.
        deep = wait_sync_counts(
            short_secondary,
            lambda counts: counts["exact_suffix_blocks"] == [18],
        )
        assert_no_sync_failures("deep-gap", short_secondary.log_text())
        require(deep["snapshot_installs"] == 1, f"deep gap snapshot count: {deep}")
        require(deep["snapshot_boundaries"] == [30], f"deep boundary is not h=30: {deep}")
        require(
            deep["exact_suffix_blocks"] == [18],
            f"deep post-snapshot suffix is not exactly 18 blocks: {deep}",
        )
        require(
            deep["exact_suffix_terminal_verifications"] == 1,
            f"deep suffix did not verify exactly one tip terminal: {deep}",
        )
        require(deep["applied_p2p_blocks"] == 0, f"deep gap used legacy blocks: {deep}")
        compare_hashes(primary, short_secondary, 0, 48)
        summary["phases"]["deep_snapshot_then_exact_sync"] = {
            "from_height": 5,
            "to_height": 48,
            "gap": 43,
            "source_startup_s": round(startup, 3),
            "elapsed_s": round(elapsed, 3),
            **deep,
        }
        summary["status"] = "passed"
        print("[PASS] 18-block boundary and deep-snapshot sync suite", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        short_secondary.stop()
        secondary.stop()
        primary.stop()
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)
    if error is not None:
        raise error


if __name__ == "__main__":
    main()
