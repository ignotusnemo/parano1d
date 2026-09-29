#!/usr/bin/env python3
"""Mine competing H10 siblings and resolve their tie on three isolated nodes.

Run with NOID_V2_LIVE_DIR set to a fresh directory inside a loopback-only
network namespace. This uses the isolated v2 node and real mined blocks.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

if "NOID_V2_LIVE_DIR" not in os.environ:
    raise SystemExit("set NOID_V2_LIVE_DIR to a fresh test directory")

import live_v2_contract_scenario as contracts

live = contracts.live
ROOT = contracts.ROOT
BASE = contracts.BASE
rpc = contracts.rpc


def main():
    devices = [line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    live.require(devices == ["lo"], "use an isolated loopback-only network namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    live.require(not BASE.exists(), f"fresh directory required: {BASE}")
    for binary in (contracts.NODE, contracts.MINER):
        live.require(binary.is_file(), f"missing binary: {binary}")
    BASE.mkdir(parents=True)
    (BASE / "logs").mkdir()
    key = BASE / "mining.key"
    key.write_text(secrets.token_hex(32) + "\n")
    key.chmod(0o600)
    live.BASE = BASE

    a = contracts.Node("miner-a", 26500, 26501)
    b = contracts.Node("miner-b", 26510, 26511)
    c = contracts.Node("observer", 26520, 26521)
    source_diff = subprocess.check_output(["git", "diff", "--binary"], cwd=ROOT)
    report = {
        "status": "running",
        "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_diff_sha256": hashlib.sha256(source_diff).hexdigest(),
        "script_sha256": live.sha256(__file__),
        "binary_sha256": {p.name: live.sha256(p) for p in (contracts.NODE, contracts.MINER)},
        "stages": [],
    }

    def checkpoint(stage):
        report["stages"].append(stage)
        (BASE / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"[stage] {stage}", flush=True)

    def mine(node, count):
        first = node.height() + 1
        with (BASE / "logs" / f"worker-{node.name}-{first}.log").open("w") as log:
            result = subprocess.run(
                [str(contracts.MINER), "--rpc", f"http://127.0.0.1:{node.rpc_port}",
                 "--key-file", str(key), "--threads", "2", "--rpc-timeout", "600",
                 "--blocks", str(count)],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                timeout=max(1800, count * 240),
            )
        live.require(result.returncode == 0 and node.height() == first + count - 1,
                     f"mining failed on {node.name} at H{first}")

    def header(node, height):
        value = rpc(node, "getBlockHeader", [height])
        live.require(value is not None, f"missing H{height} on {node.name}")
        return value

    try:
        checkpoint("mine one common legacy prefix through H9")
        b.start("01-b-common")
        c.start("02-c-common")
        a.start("03-a-common", mode="extminer", genesis=True, seeds=[b.seed, c.seed])
        mine(a, 9)
        live.wait_value("all nodes have common H9", lambda: (
            a.info()["height"] == b.info()["height"] == c.info()["height"] == 9
            and header(a, 9)["hash"] == header(b, 9)["hash"] == header(c, 9)["hash"]
        ), 900)
        common = header(a, 9)["hash"]
        b.stop()
        c.stop()

        checkpoint("mine first v2 child while other nodes are stopped")
        mine(a, 1)
        first = header(a, 10)
        a.stop()
        time.sleep(2)

        checkpoint("mine a competing v2 child from the same parent")
        b.start("04-b-isolated", mode="extminer", genesis=True)
        live.require(header(b, 9)["hash"] == common and b.height() == 9,
                     "second miner lost the common parent")
        mine(b, 1)
        second = header(b, 10)
        b.stop()
        live.require(first["prev_hash"] == second["prev_hash"] == common,
                     "competing blocks do not share H9")
        live.require(first["hash"] != second["hash"], "miners found identical H10 blocks")
        live.require(first["timestamp"] != second["timestamp"],
                     "competing timestamps did not differ")
        live.require(first["difficulty_target"] == second["difficulty_target"],
                     "v2 siblings with different timestamps have different targets")
        winning_hash = min(first["hash"], second["hash"])
        report.update(common_h9=common, first_h10=first, second_h10=second,
                      expected_h10=winning_hash)

        checkpoint("reconnect three nodes and resolve equal work by hash")
        a.start("05-a-rejoined", mode="extminer", genesis=True)
        b.start("06-b-rejoined", mode="extminer", genesis=True, seeds=[a.seed])
        c.start("07-c-observer", seeds=[a.seed, b.seed])
        live.wait_value("all nodes select the deterministic H10 winner", lambda: (
            all(node.height() == 10 and header(node, 10)["hash"] == winning_hash
                for node in (a, b, c))
        ), 900)

        checkpoint("mine a successor and verify three-node convergence")
        winner = a if first["hash"] == winning_hash else b
        mine(winner, 1)
        live.wait_value("all nodes accept H11", lambda: (
            all(node.height() == 11 for node in (a, b, c))
            and len({header(node, 11)["hash"] for node in (a, b, c)}) == 1
        ), 900)
        report.update(status="passed", final_h11=header(winner, 11)["hash"])
        checkpoint("complete")
    except Exception as error:
        report.update(status="failed", error=str(error))
        checkpoint("failed")
        raise
    finally:
        for node in (a, b, c):
            node.request_stop()
        for node in (a, b, c):
            try:
                node.finish_stop()
            except Exception as error:
                report.setdefault("shutdown_errors", []).append(str(error))
        (BASE / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
