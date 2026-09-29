#!/usr/bin/env python3
"""Replace a v2 fork origin over P2P and roll back a confirmed integer call.

Run in a fresh loopback-only network namespace with NOID_V2_LIVE_DIR pointing
to a new directory. Uses the same pinned candidate binaries as the contract
scenario. Both branches mine real proofs; no headers or State are injected.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import live_v2_contract_scenario as contracts

live = contracts.live
BASE = contracts.BASE
ROOT = contracts.ROOT
rpc = contracts.rpc


def main():
    devices = [line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    live.require(devices == ["lo"], "use an isolated loopback-only network namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    live.require(not BASE.exists(), f"fresh directory required: {BASE}")
    BASE.mkdir(parents=True)
    (BASE / "logs").mkdir()
    key = BASE / "mining.key"
    with key.open("x") as file:
        file.write(secrets.token_hex(32) + "\n")
    key.chmod(0o600)
    live.BASE = BASE
    a = contracts.Node("branch-a", 26400, 26401)
    b = contracts.Node("branch-b", 26410, 26411)
    report = {"status": "running", "stages": [], "mining": [],
              "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "script_sha256": {Path(p).name: live.sha256(p) for p in (__file__, contracts.__file__, live.__file__)},
              "binary_sha256": {p.name: live.sha256(p) for p in (contracts.NODE, contracts.MINER)}}

    def checkpoint(stage):
        report["stage"] = stage
        report["stages"].append(stage)
        (BASE / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"[stage] {stage}", flush=True)

    def converge():
        return live.wait_value("both nodes select exactly the same tip", lambda: live.exact_tip(a, b), 900)

    def mine(node, count):
        first = node.height() + 1
        start = time.monotonic()
        with (BASE / "logs" / f"worker-{node.name}-{first}.log").open("w") as log:
            result = subprocess.run([str(contracts.MINER), "--rpc", f"http://127.0.0.1:{node.rpc_port}",
                "--key-file", str(key), "--threads", "2", "--rpc-timeout", "600", "--blocks", str(count)],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=max(900, count * 180))
        live.require(result.returncode == 0 and node.height() == first + count - 1, "finite mining failed")
        report["mining"].append({"node": node.name, "first": first, "last": node.height(),
                                  "seconds": time.monotonic() - start})

    def branch_work(node):
        # Match the protocol's strict-less-than target accounting. The two
        # branches are mined sequentially, so ASERT may assign different work
        # per block; a greater height alone does not establish the winner.
        work = 0
        for height in range(9, node.height() + 1):
            target = int.from_bytes(bytes.fromhex(rpc(node, "getBlockHeader", [height])["difficulty_target"]), "little")
            live.require(target > 0, "invalid proof-of-work target")
            work += ((1 << 256) - 1) // target + 1
        return work

    try:
        checkpoint("common real legacy prefix through H8")
        b.start("01-b-common")
        a.start("02-a-common", mode="extminer", genesis=True, seeds=[b.seed])
        mine(a, 8)
        converge()
        common = a.info()
        live.require(common["height"] == 8, "wrong common height")
        b.stop()

        checkpoint("branch A crosses H10, funds and calls a persistent counter")
        mine(a, 2)
        boundary_a = rpc(a, "getBlockHash", [9])
        owner = rpc(a, "walletActiveAddress")["address"]
        definition = {"kind": "custom_program", "definition": {
            "state": ["0", "0"],
            "program": [{"opcode": "add", "destination": "state0", "left": "state0", "right": "one",
                         "predicate": {"source": "terminal", "inverted": True}, "immediate": "0"}],
            "claim_authority": owner, "recovery_authority": owner,
            "claim_recipient": owner, "recovery_recipient": owner,
            "deadline_height": 100, "max_fee_micronoid": 1000000,
            "max_payout_micronoid": 1000000, "min_retained_micronoid": 0,
            "claim_can_continue": True, "claim_can_close": True,
            "recovery_can_continue": False, "recovery_can_close": True,
            "unrestricted_payout_recipient": False}}
        opening = rpc(a, "createObject", [definition])
        funding = rpc(a, "walletFundObject", [opening["opening_hex"], 10000000, 0])
        pending_funding = rpc(a, "getMempoolEntry", [funding["txid"]])
        live.require(pending_funding is not None and pending_funding["tx_hash"] == funding["txid"]
                     and pending_funding["contract_opening_hex"] is None,
                     "ordinary funding unexpectedly carries a contract opening")
        mine(a, 1)
        slot = contracts.output_for(a, funding["txid"], opening["address"])
        live.require(slot is not None, "contract not funded at H11")
        request = {"opening_hex": opening["opening_hex"], "slot_index": slot["slot_index"],
                   "creation_id": slot["creation_id"], "terminal": False,
                   "fee_micronoid": 0, "expected_authority": owner}
        preview = rpc(a, "previewObjectCall", [request])
        request.update(expected_txid=preview["txid"], expected_call_height=preview["call_height"],
                       expected_recovery=preview["recovery"])
        call = rpc(a, "walletCallObject", [request])
        txid = call["transaction"]["txid"]
        pending_call = rpc(a, "getMempoolEntry", [txid])
        live.require(pending_call is not None and pending_call["tx_hash"] == txid
                     and pending_call["contract_opening_hex"] == opening["opening_hex"],
                     "pending call does not expose its admitted public opening")
        bulk_call = next((entry for entry in rpc(a, "getMempoolInfo")["txs"]
                          if entry["tx_hash"] == txid), None)
        live.require(bulk_call is not None and "contract_opening_hex" not in bulk_call,
                     "bulk mempool metadata unexpectedly contains opening bytes")
        mine(a, 1)
        live.require(rpc(a, "getTx", [txid]) is not None, "call not confirmed at H12")
        live.require(rpc(a, "getMempoolEntry", [txid]) is None,
                     "confirmed call still appears in the mempool")
        call_rows = rpc(a, "getBlockDetails", [12])["retained"]["transactions"]
        live.require(next(row for row in call_rows if row["txid"] == txid)["contract"] == "call",
                     "retained call is not marked as a contract transition")
        live.require(call["successor"]["state"] == ["1", "0"], "counter state differs")
        receipt = rpc(a, "exportObjectReceipt", [opening["opening_hex"], txid])
        live.require(rpc(a, "verifyObjectReceipt", [receipt])["valid"], "initial call receipt invalid")
        (BASE / "orphaned-call.receipt").write_bytes(bytes.fromhex(receipt))
        a_work = branch_work(a)
        report.update(common=common, branch_a=a.info(), branch_a_work=str(a_work), old_origin_header=boundary_a,
                      opening=opening, call=call, funding=funding,
                      rpc_indexing={"pending_opening_bytes": len(pending_call["contract_opening_hex"]) // 2,
                                    "retained_contract": "call", "bulk_metadata_only": True})
        a.stop()

        checkpoint("branch B builds an independent H9 origin and strictly greater work")
        b.start("03-b-competing", mode="extminer", genesis=True)
        live.require(b.height() == 8, "branch B lost the common prefix")
        mine(b, 5)
        while branch_work(b) <= a_work:
            live.require(b.height() < 24, "competing branch did not overtake within the bounded scenario")
            mine(b, 1)
        winning_height = b.height()
        boundary_b = rpc(b, "getBlockHash", [9])
        live.require(boundary_b != boundary_a, "competing fork origin did not change")
        report.update(branch_b=b.info(), branch_b_work=str(branch_work(b)), new_origin_header=boundary_b)
        b.stop()

        checkpoint("P2P reorg crosses the v2 boundary and invalidates the old call")
        b.start("04-b-winner")
        a.start("05-a-reorganizes", seeds=[b.seed])
        start = time.monotonic()
        converge()
        report["reorg_seconds"] = time.monotonic() - start
        for height in range(1, winning_height + 1):
            live.require(rpc(a, "getBlockHash", [height]) == rpc(b, "getBlockHash", [height]),
                         f"canonical hash differs at H{height}")
        live.require(rpc(a, "getBlockHash", [9]) == boundary_b, "old origin still selected")
        live.require(rpc(a, "getTx", [txid]) is None, "orphaned call still reported confirmed")
        report["orphan_receipt_rejected"] = contracts.rejected(a, "verifyObjectReceipt", [receipt])
        report["orphan_export_rejected"] = contracts.rejected(a, "exportObjectReceipt", [opening["opening_hex"], txid])
        for info in (opening, call["successor"]):
            live.require(rpc(a, "walletGetObjectOpening", [info["address"]])["opening_hex"] == info["opening_hex"],
                         "reorg discarded retained public terms")
            live.require(rpc(a, "getObjectInstances", [info["opening_hex"], 0, 64])["slots"] == [],
                         "orphaned contract instance survived State rollback")
        report["orphan_call_rejected"] = contracts.rejected(a, "walletCallObject", [request])
        log = a.log_path.read_text(errors="replace")
        live.require("reorg complete" in log, "no reorg completion evidence")

        checkpoint("restart after origin replacement and mine its v2 successor")
        a.stop()
        a.start("06-a-reopened", mode="extminer", seeds=[b.seed])
        converge()
        mine(a, 1)
        converge()
        live.require(a.height() == winning_height + 1, "new selected origin cannot produce its successor")
        report.update(status="passed", final_tip=a.info())
        checkpoint("complete")
    except Exception as error:
        report.update(status="failed", error=str(error))
        checkpoint("failed")
        raise
    finally:
        for node in (a, b):
            node.request_stop()
        for node in (a, b):
            try:
                node.finish_stop()
            except Exception as error:
                report.setdefault("shutdown_errors", []).append(str(error))
        (BASE / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
