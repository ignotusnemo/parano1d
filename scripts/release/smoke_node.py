#!/usr/bin/env python3
"""Check the embedded native runtime and ancestry certificate in a fresh node."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def check(node, retirement_origin, timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    expected_origin = retirement_origin.read_bytes() if retirement_origin else None
    with tempfile.TemporaryDirectory(prefix="parano1d-release-smoke-") as directory:
        root = Path(directory)
        data = root / "data"
        rpc_port = free_port()
        endpoint = f"http://127.0.0.1:{rpc_port}"

        def rpc(method):
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "paranoid_" + method, "params": []}).encode()
            request = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=2) as response:
                result = json.load(response)
            if "error" in result:
                raise ValueError(f"{method}: {result['error']}")
            return result["result"]

        with (root / "node.log").open("w+", encoding="utf-8") as log:
            process = subprocess.Popen([
                str(node), "--config", str(root / "node.toml"),
                "--data-dir", str(data), "--mode", "node", "--disable-dns-seeds",
                "--p2p-listen", "127.0.0.1:0", "--rpc-listen", f"127.0.0.1:{rpc_port}",
                "--log", "warn",
            ], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + timeout
                while True:
                    if process.poll() is not None:
                        raise ValueError(f"release daemon exited with status {process.returncode}")
                    try:
                        status = rpc("getNodeStatus")
                        break
                    except (urllib.error.URLError, TimeoutError, ConnectionError):
                        if time.monotonic() >= deadline:
                            raise ValueError("release daemon RPC startup timed out")
                        time.sleep(0.25)
                protocol = rpc("getNativeProtocol")
                chain = rpc("getChainInfo")
                if status["testnet"] or status["mining"] or status["p2p_connected_peers"]:
                    raise ValueError("release smoke node must be isolated mainnet with mining off")
                if chain["height"] != 0 or protocol["tip_height"] != 0:
                    raise ValueError("release smoke node must start from a fresh chain")
                if not protocol["runtime_available"] or not protocol["activation_height"]:
                    raise ValueError("scheduled native runtime is missing")
                if expected_origin is not None:
                    retained = list((data / "fork-origins").glob("*.origin"))
                    if not expected_origin or not any(path.read_bytes() == expected_origin for path in retained):
                        raise ValueError("embedded ancestry certificate was not verified and retained")
                return {
                    "native_runtime": "ready",
                    "activation_height": protocol["activation_height"],
                    "ancestry_certificate": "verified" if expected_origin is not None else "transition profile",
                    "isolated": True,
                }
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read()[-8000:])
                raise
            finally:
                if process.poll() is None:
                    if os.name == "nt":
                        process.terminate()
                    else:
                        process.send_signal(signal.SIGINT)
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--retirement-origin", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    try:
        result = check(args.node.resolve(), args.retirement_origin, args.timeout)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"release node check: {error}\n")
    print("Release node check passed: " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
