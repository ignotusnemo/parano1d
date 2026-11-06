#!/usr/bin/env python3
"""Check old/new mainnet daemons against a closed chain fixture, without mining.

Run inside a loopback-only network namespace. The source database must have
been closed cleanly. Every daemon uses a separate copy or a fresh database.
"""

import argparse
import hashlib
import json
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request


def require(condition, message):
    if not condition:
        raise ValueError(message)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Node:
    def __init__(self, binary, root):
        self.binary = binary
        self.root = root
        self.data = root / "data"
        self.p2p = free_port()
        self.rpc_port = free_port()
        self.process = None
        self.log = None
        self.root.mkdir(parents=True, exist_ok=True)
        (root / "node.toml").write_text(
            '[network]\nseeds = []\npublic_addresses = []\n'
            '[storage]\nbackend = "mdbx"\npath = "unused-by-cli"\n'
            '[rpc]\n'
            '[mining]\nenabled = false\nminer_address = ""\n'
        )

    @property
    def seed(self):
        return f"127.0.0.1:{self.p2p}"

    def rpc(self, method, params=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.rpc_port}",
            data=json.dumps({"jsonrpc": "2.0", "id": 1,
                             "method": "paranoid_" + method,
                             "params": params or []}).encode(),
            headers={"Content-Type": "application/json"},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=15) as response:
            result = json.load(response)
        if "error" in result:
            raise ValueError(str(result["error"]))
        return result["result"]

    def start(self, label, seed=None):
        require(self.process is None, "node already running")
        self.log = (self.root / f"{label}.log").open("wb")
        args = [str(self.binary), "--config", str(self.root / "node.toml"),
                "--data-dir", str(self.data), "--mode", "node",
                "--disable-dns-seeds", "--p2p-listen", self.seed,
                "--rpc-listen", f"127.0.0.1:{self.rpc_port}", "--log", "info"]
        if seed:
            args += ["--seed", seed]
        self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=subprocess.STDOUT)
        self.wait(lambda: self.rpc("getNodeStatus"), 180)
        require(not self.rpc("getNodeStatus")["mining"], "mining must be disabled")

    def wait(self, check, timeout):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            require(self.process.poll() is None, f"node exited: {self.root}")
            try:
                value = check()
                if value:
                    return value
            except (OSError, ValueError) as error:
                last = str(error)
            time.sleep(0.5)
        raise TimeoutError(f"node check timed out: {self.root}, last={last}")

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGINT)
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
                    raise ValueError(f"node shutdown timed out: {self.root}")
            require(self.process.returncode == 0,
                    f"node failed: {self.root}, exit={self.process.returncode}")
            self.process = None
            self.log.close()

    def snapshot(self):
        chain = self.rpc("getChainInfo")
        header = self.rpc("getBlockDetails", [chain["height"]])["header"]
        return {"chain": chain, "header": header}

    def rss_kib(self):
        return int(next(line.split()[1] for line in
                        Path(f"/proc/{self.process.pid}/status").read_text().splitlines()
                        if line.startswith("VmRSS:")))


def check(args):
    devices = [line.split(":")[0].strip()
               for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    require(devices == ["lo"], "run in a loopback-only network namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    require(not args.output.exists(), "output directory must be fresh")
    args.output.mkdir(parents=True)
    report = {"status": "running", "mining": False, "checks": [],
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "binaries": {key: {"version": subprocess.check_output(
                  [str(path), "--version"], text=True).strip(),
                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "bytes": path.stat().st_size}
                  for key, path in [("old", args.old_node), ("new", args.new_node)]}}
    nodes = [Node(args.old_node, args.output / "source"),
             Node(args.new_node, args.output / "new"),
             Node(args.old_node, args.output / "old"),
             Node(args.new_node, args.output / "upgraded")]
    source, new, old, upgraded = nodes
    for node in (source, upgraded):
        subprocess.run(["cp", "-a", "--reflink=auto", "--sparse=always",
                        str(args.source_data), str(node.data)], check=True)
        # Cached public addresses belong to the original internet fixture.
        (node.data / "peers.json").unlink(missing_ok=True)

    def retained_origins(node):
        files = list((node.data / "fork-origins").glob("*.origin"))
        unified = [p for p in files if p.read_bytes().startswith(b"O1A4OR02")]
        previous = [p for p in files if p.read_bytes().startswith(b"O1V2OR02")]
        require(len(files) == 2 and len(unified) == len(previous) == 1,
                "expected a unified certificate and its original predecessor")
        original = source.data / "fork-origins" / previous[0].name
        require(previous[0].read_bytes() == original.read_bytes(),
                "retained predecessor differs from the original certificate")
        return {"unified_bytes": unified[0].stat().st_size,
                "predecessor_bytes": previous[0].stat().st_size}

    def record(label, node, expected):
        started = time.monotonic()
        node.wait(lambda: node.rpc("getChainInfo") == expected["chain"], args.timeout)
        require(node.snapshot() == expected, f"chain or state differs: {label}")
        report["checks"].append({"stage": label, "seconds": time.monotonic() - started,
                                 "rss_kib": node.rss_kib(), "tip": expected})
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(label, "passed", flush=True)

    try:
        source.start("source")
        expected = source.snapshot()
        require(expected["chain"]["height"] >= 279370, "fixture must include v2.1")
        report["fixture"] = expected
        upgraded.start("existing-data-upgrade")
        record("2.1.1 upgrade of existing 2.1 data", upgraded, expected)
        require(upgraded.rpc("getNodeStatus")["p2p_connected_peers"] == 0,
                "existing-data upgrade contacted a peer")
        report["upgraded_retained_certificates"] = retained_origins(upgraded)
        upgraded.stop()
        new.start("cold-from-old", source.seed)
        record("2.1.1 cold sync from 2.1", new, expected)
        require("snapshot install completed" in
                (new.root / "cold-from-old.log").read_text(), "snapshot path not exercised")
        # Stop the original provider so an old receiver must obtain all data,
        # including the legacy origin representation, from the new daemon.
        source.stop()
        old.start("cold-from-new", new.seed)
        record("2.1 cold sync from 2.1.1", old, expected)
        for original in (source.data / "fork-origins").glob("*.origin"):
            if original.read_bytes().startswith(b"O1A4OR01"):
                require((old.data / "fork-origins" / original.name).read_bytes()
                        == original.read_bytes(), "legacy export differs from original bytes")
                report["legacy_export_byte_identical"] = True
        require(report.get("legacy_export_byte_identical"), "legacy export not checked")
        old.stop()
        new.stop()
        (new.data / "peers.json").unlink(missing_ok=True)
        # Startup reconstructs the predecessor from the embedded complete
        # certificate even when its ordinary cache file has been removed.
        previous = [p for p in (new.data / "fork-origins").glob("*.origin")
                    if p.read_bytes().startswith(b"O1V2OR02")]
        require(len(previous) == 1, "one retained predecessor expected")
        previous[0].unlink()
        new.start("offline-restart")
        record("2.1.1 offline restart", new, expected)
        require(new.rpc("getNodeStatus")["p2p_connected_peers"] == 0,
                "offline restart contacted a peer")
        report["retained_certificates"] = retained_origins(new)
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        for node in nodes:
            try:
                node.stop()
            except Exception as error:
                report.setdefault("shutdown_errors", []).append(str(error))
                report["status"] = "failed"
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    require(report["status"] == "passed", "shutdown check failed")
    print(json.dumps({"status": report["status"],
                      "checks": len(report["checks"]),
                      "legacy_export_byte_identical": True}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-node", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--new-node", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--source-data", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--output", type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--timeout", type=float, default=1200)
    check(parser.parse_args())
