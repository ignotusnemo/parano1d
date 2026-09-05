#!/usr/bin/env python3
"""Fresh-chain payment-receipt lifecycle scenario.

This scenario covers receipts only. It uses the current production release
binary and a chain mined from genesis in this invocation:

- create and confirm one ordinary payment;
- inspect the exact durable receipt file;
- verify the receipt on the sender and an independent connected node;
- expose the Merkle-authenticated payment summary through RPC and CLI;
- reject content and canonical-header tampering;
- restart and recover the byte-identical receipt from disk;
- prune the source block body, restart again, and verify from the permanent
  canonical header without relying on retained transaction bodies.
"""

import datetime
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_RECEIPT_DIR",
        str(RUN_PARENT / f"receipt-lifecycle-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_RECEIPT_BASE_PORT", "22900"))
PAYMENT_MICRONOID = int(os.environ.get("NOID_LIVE_RECEIPT_PAYMENT", "1000000"))
FUNDING_HEIGHT = int(os.environ.get("NOID_LIVE_RECEIPT_FUNDING_HEIGHT", "3"))
# Full bodies remain serveable beyond the 18-block authenticated suffix so a
# peer can recover a moving non-final branch.  Receipt independence must be
# tested only after that complete operational serving window has elapsed.
RETAINED_BLOCK_SERVING_DEPTH = 42
CLI_BIN = ROOT / "target" / "release" / "parano1d-cli"

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


FAILURE_MARKERS = (
    " ERROR ",
    "panicked",
    "receipt recovery failed",
    "wallet receipt recovery",
    "P2P block rejected",
    "reorg failed",
)


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def assert_clean(label):
    failures = [
        line
        for line in log_text(label).splitlines()
        if any(marker in line for marker in FAILURE_MARKERS)
    ]
    require(not failures, f"{label} contains failures: {failures[-10:]}")


def wait_value(label, probe, timeout=900, interval=0.25):
    return live.wait_value(label, probe, timeout=timeout, interval=interval)


def wait_tx(node, txid, timeout=900):
    return wait_value(
        f"{node.name} indexes transaction {txid[:12]}",
        lambda: rpc(node.rpc_port, "getTx", [txid]),
        timeout=timeout,
    )


def wait_same_tip(left, right, timeout=180):
    return wait_value(
        f"{left.name}/{right.name} exact tip convergence",
        lambda: live.exact_tip(left, right),
        timeout=timeout,
        interval=0.5,
    )


def export_receipt(node, txid, timeout=120):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            receipt = rpc(
                node.rpc_port, "walletExportReceipt", [txid], timeout=30
            )
            if receipt:
                print(
                    f"[ok] wallet receipt {txid[:12]} is durable "
                    f"bytes={len(receipt) // 2}",
                    flush=True,
                )
                return receipt
            last = receipt
        except live.LiveForkReorgError as error:
            last = str(error)
        time.sleep(0.25)
    raise live.LiveForkReorgError(
        f"timeout waiting for durable wallet receipt {txid}; last={last}"
    )


def cli(node, args, json_mode=False, check=True, timeout=120):
    command = [
        str(CLI_BIN),
        "--rpc",
        f"http://127.0.0.1:{node.rpc_port}",
    ]
    if json_mode:
        command.append("--json")
    command.extend(args)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    print(f"[cli] {node.name}$ {' '.join(args)} -> {completed.returncode}", flush=True)
    if check:
        require(
            completed.returncode == 0,
            f"CLI failed: {command}\nstdout={completed.stdout}\nstderr={completed.stderr}",
        )
    return completed


def assert_verified(result, txid, height, sender, recipient, amount, fee, label):
    require(result["merkle_valid"], f"{label}: invalid Merkle path: {result}")
    require(result["canonical"], f"{label}: non-canonical receipt: {result}")
    require(result["confirmed"], f"{label}: unconfirmed receipt: {result}")
    summary = result.get("authenticated_summary")
    require(summary is not None, f"{label}: authenticated summary missing")
    require(summary["txid"] == txid, f"{label}: wrong txid: {summary}")
    require(int(summary["claimed_height"]) == height, f"{label}: wrong height: {summary}")
    require(int(summary["fee_micronoid"]) == fee, f"{label}: wrong fee: {summary}")
    require(len(summary["inputs"]) == 1, f"{label}: wrong input count: {summary}")
    require(summary["inputs"][0]["owner"] == sender, f"{label}: wrong input owner")
    recipient_outputs = [
        output
        for output in summary["outputs"]
        if output["owner"] == recipient and int(output["amount_micronoid"]) == amount
    ]
    require(len(recipient_outputs) == 1, f"{label}: payment output missing: {summary}")
    require(
        any(output["owner"] == sender for output in summary["outputs"]),
        f"{label}: sender change output missing: {summary}",
    )
    return summary


def content_tamper(node, receipt_hex):
    original = bytes.fromhex(receipt_hex)
    # Skip the bincode marker/length prefix. A one-bit mutation inside the
    # canonical PagedSpend often remains decodable but changes its logical
    # leaf, which the fixed Merkle path must reject.
    for offset in range(16, min(len(original) - 16, 512)):
        candidate = bytearray(original)
        candidate[offset] ^= 1
        try:
            result = rpc(node.rpc_port, "verifyReceipt", [candidate.hex()])
        except live.LiveForkReorgError:
            continue
        if not result["merkle_valid"] and not result["confirmed"]:
            print(f"[tamper] content mutation rejected at byte={offset}", flush=True)
            return offset, candidate.hex(), result
    raise live.LiveForkReorgError("could not find a decodable content mutation")


def stop_if_running(node, cleanup):
    if node.proc is None or node.proc.poll() is not None:
        return
    try:
        node.stop()
    except Exception as error:
        cleanup.append(str(error))


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(CLI_BIN.is_file(), f"release CLI is missing: {CLI_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    ports = (BASE_PORT, BASE_PORT + 1, BASE_PORT + 10, BASE_PORT + 11)
    for port in ports:
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_RECEIPT_RUN").write_text(str(BASE) + "\n")

    sender_node = Node("sender-miner", BASE_PORT, BASE_PORT + 1)
    verifier_node = Node("independent-verifier", BASE_PORT + 10, BASE_PORT + 11)
    labels = []
    cleanup = []
    error = None
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "cli_sha256": live.sha256(CLI_BIN),
        "payment_micronoid": PAYMENT_MICRONOID,
        "status": "running",
    }
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={summary['binary_sha256']} size={summary['binary_size']}",
        flush=True,
    )

    try:
        setup_label = "01-sender-wallet-setup-h0"
        sender_node.start(setup_label)
        labels.append(setup_label)
        sender_info = rpc(sender_node.rpc_port, "walletActiveAddress")
        recipient_info = rpc(sender_node.rpc_port, "walletNextAddress")
        require(int(sender_info["key_index"]) == 0, f"unexpected sender: {sender_info}")
        require(int(recipient_info["key_index"]) == 1, f"unexpected recipient: {recipient_info}")
        rpc(sender_node.rpc_port, "walletSetActiveAddress", [0])
        sender_node.stop()

        mining_label = "02-fresh-genesis-payment-miner"
        sender_node.start(mining_label, mode="miner", genesis=True)
        labels.append(mining_label)

        verifier_label = "03-independent-connected-verifier"
        verifier_node.start(verifier_label, seeds=[sender_node.seed])
        labels.append(verifier_label)
        wait_value(
            "receipt peers connect",
            lambda: int(rpc(sender_node.rpc_port, "getPeerCount")) >= 1
            and int(rpc(verifier_node.rpc_port, "getPeerCount")) >= 1,
            timeout=120,
        )

        live.wait_mined(sender_node, FUNDING_HEIGHT, timeout=900)
        rpc(sender_node.rpc_port, "walletScan", timeout=180)
        sent = rpc(
            sender_node.rpc_port,
            "walletSend",
            [recipient_info["address"], PAYMENT_MICRONOID, 0],
            timeout=300,
        )
        txid = sent["txid"]
        confirmation = wait_tx(sender_node, txid)
        tx_height = int(confirmation["height"])
        wait_tx(verifier_node, txid)
        receipt_hex = export_receipt(sender_node, txid)
        require(len(receipt_hex) % 2 == 0 and len(receipt_hex) > 100, "invalid receipt hex")

        sender_verify = rpc(sender_node.rpc_port, "verifyReceipt", [receipt_hex])
        verifier_verify = rpc(verifier_node.rpc_port, "verifyReceipt", [receipt_hex])
        authenticated_summary = assert_verified(
            sender_verify,
            txid,
            tx_height,
            sender_info["address"],
            recipient_info["address"],
            PAYMENT_MICRONOID,
            int(sent["fee_micronoid"]),
            "sender verification",
        )
        assert_verified(
            verifier_verify,
            txid,
            tx_height,
            sender_info["address"],
            recipient_info["address"],
            PAYMENT_MICRONOID,
            int(sent["fee_micronoid"]),
            "independent verification",
        )

        receipts_path = sender_node.data_dir / "wallet.receipts"
        durable_bytes = receipts_path.read_bytes()
        if durable_bytes.startswith(b"NOIDRCJ1"):
            # The production decoder/checksums are exercised by both restarts
            # below. Keep this physical-persistence check compatible with the
            # incremental journal without duplicating its decoder in Python.
            require(receipt_hex.encode("ascii") in durable_bytes, "durable receipt bytes missing")
        else:
            durable_receipts = json.loads(durable_bytes)
            require(durable_receipts.get(txid) == receipt_hex, "durable receipt bytes differ")

        cli_receipt = cli(sender_node, ["receipt", txid]).stdout.strip()
        require(cli_receipt == receipt_hex, "CLI exported different receipt bytes")
        cli_verified = cli(verifier_node, ["verify", receipt_hex])
        require("Receipt is VALID and canonical" in cli_verified.stdout, "CLI omitted verdict")
        require("Authenticated payment" in cli_verified.stdout, "CLI omitted payment summary")
        require(txid in cli_verified.stdout, "CLI omitted authenticated txid")
        require(recipient_info["address"] in cli_verified.stdout, "CLI omitted recipient")
        cli_json = json.loads(
            cli(verifier_node, ["verify", receipt_hex], json_mode=True).stdout
        )
        require(cli_json == verifier_verify, "CLI JSON and RPC receipt results differ")

        content_offset, content_bad_hex, content_bad = content_tamper(
            verifier_node, receipt_hex
        )
        content_cli = cli(
            verifier_node,
            ["verify", content_bad_hex],
            check=False,
        )
        require(content_cli.returncode != 0, "CLI accepted content-tampered receipt")

        canonical_bad = bytearray.fromhex(receipt_hex)
        canonical_bad[-1] ^= 1
        canonical_bad_hex = canonical_bad.hex()
        canonical_bad_result = rpc(
            verifier_node.rpc_port, "verifyReceipt", [canonical_bad_hex]
        )
        require(
            not canonical_bad_result["confirmed"]
            and not canonical_bad_result["canonical"],
            f"canonical-header tamper verified: {canonical_bad_result}",
        )
        canonical_cli = cli(
            verifier_node,
            ["verify", canonical_bad_hex],
            check=False,
        )
        require(canonical_cli.returncode != 0, "CLI accepted header-tampered receipt")

        sender_node.stop()
        restart_label = "04-durable-receipt-restart-and-prune"
        restart_info, restart_seconds = sender_node.start(
            restart_label,
            mode="miner",
            genesis=True,
            seeds=[verifier_node.seed],
        )
        labels.append(restart_label)
        require(export_receipt(sender_node, txid) == receipt_hex, "restart changed receipt bytes")
        assert_verified(
            rpc(sender_node.rpc_port, "verifyReceipt", [receipt_hex]),
            txid,
            tx_height,
            sender_info["address"],
            recipient_info["address"],
            PAYMENT_MICRONOID,
            int(sent["fee_micronoid"]),
            "post-restart verification",
        )

        prune_height = tx_height + RETAINED_BLOCK_SERVING_DEPTH + 1
        live.wait_mined(sender_node, prune_height, timeout=1800)
        wait_value(
            "independent verifier reaches pruning horizon",
            lambda: verifier_node.height() >= prune_height,
            timeout=300,
        )
        require(
            rpc(sender_node.rpc_port, "getBlock", [tx_height]) is None,
            "source block body was not pruned",
        )
        require(
            rpc(verifier_node.rpc_port, "getBlock", [tx_height]) is None,
            "verifier retained the pruned source block body",
        )
        require(rpc(sender_node.rpc_port, "getTx", [txid]) is not None, "tx index was pruned")
        post_prune_verify = rpc(verifier_node.rpc_port, "verifyReceipt", [receipt_hex])
        assert_verified(
            post_prune_verify,
            txid,
            tx_height,
            sender_info["address"],
            recipient_info["address"],
            PAYMENT_MICRONOID,
            int(sent["fee_micronoid"]),
            "post-prune independent verification",
        )

        sender_node.stop()
        final_label = "05-post-prune-receipt-restart"
        final_info, final_restart_seconds = sender_node.start(
            final_label, seeds=[verifier_node.seed]
        )
        labels.append(final_label)
        require(export_receipt(sender_node, txid) == receipt_hex, "post-prune restart lost receipt")
        final_verify = rpc(sender_node.rpc_port, "verifyReceipt", [receipt_hex])
        assert_verified(
            final_verify,
            txid,
            tx_height,
            sender_info["address"],
            recipient_info["address"],
            PAYMENT_MICRONOID,
            int(sent["fee_micronoid"]),
            "post-prune restart verification",
        )
        require(
            rpc(sender_node.rpc_port, "getBlock", [tx_height]) is None,
            "post-prune restart resurrected block body",
        )
        wait_same_tip(sender_node, verifier_node, timeout=180)

        sender_node.stop()
        verifier_node.stop()
        for label in labels:
            assert_clean(label)

        summary.update(
            {
                "status": "passed",
                "sender": sender_info,
                "recipient": recipient_info,
                "transaction": sent,
                "confirmation": confirmation,
                "receipt_bytes": len(receipt_hex) // 2,
                "receipt_sha256": hashlib.sha256(bytes.fromhex(receipt_hex)).hexdigest(),
                "durable_receipt_file_bytes": receipts_path.stat().st_size,
                "authenticated_summary": authenticated_summary,
                "sender_verification": sender_verify,
                "independent_verification": verifier_verify,
                "content_tamper_byte": content_offset,
                "content_tamper_result": content_bad,
                "canonical_tamper_result": canonical_bad_result,
                "restart_height": restart_info["height"],
                "restart_seconds": restart_seconds,
                "prune_height": prune_height,
                "post_prune_verification": post_prune_verify,
                "final_restart_height": final_info["height"],
                "final_restart_seconds": final_restart_seconds,
                "final_verification": final_verify,
                "logs": labels,
            }
        )
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
    finally:
        stop_if_running(sender_node, cleanup)
        stop_if_running(verifier_node, cleanup)
        if cleanup:
            summary["cleanup_errors"] = cleanup
        summary_path = BASE / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(f"[summary] {summary_path}", flush=True)

    if error is not None:
        raise error
    require(not cleanup, f"cleanup failed: {cleanup}")
    print("RECEIPT LIFECYCLE LIVE SCENARIO PASSED", flush=True)


if __name__ == "__main__":
    main()
