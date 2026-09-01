# External miner

External mining separates PoW nonce search from the node. The node still owns
the mempool, transaction selection, State transition, `HistoryStep` proof,
template and block relay.

The worker receives no block body or proving witness.

## Local worker

Create one protected token file and use it for the node and local worker:

```sh
umask 077
openssl rand -hex 32 > ~/.parano1d/mining.key

parano1d --mode extminer --mining-key-file ~/.parano1d/mining.key
```

In another terminal:

```sh
parano1d-miner \
  --rpc http://127.0.0.1:9601 \
  --key-file ~/.parano1d/mining.key
```

Originless local clients may omit Authorization on loopback so the GUI and CLI keep full local administration without a password. Keep `--key-file` on the external miner even when it runs locally so its requests receive only the mining scope. A native local process that deliberately omits the key is treated as a trusted local owner process. The legacy `--mining-key TOKEN` and `--key TOKEN` forms remain compatible, but their values can be visible in process arguments. A key file must be owned by the current user and inaccessible to group and others on Unix.

Limit worker threads when needed:

```sh
parano1d-miner --key-file ~/.parano1d/mining.key --threads 8
```

## Remote worker

Do not expose an unencrypted bearer token directly to the Internet. The RPC server supports HTTP only and rejects WebSocket upgrades.

Place the worker and node on an authenticated private network, or terminate TLS and restrict the exposed path at a reverse proxy. Bind remote RPC only after that transport is in place:

```sh
parano1d \
  --mode extminer \
  --rpc-listen 0.0.0.0:9601 \
  --mining-key-file /secure/parano1d-mining.key
```

Firewall the port so only intended workers or the proxy can reach it.

## Payout

By default, templates use the node's configured payout address. This is the
safer solo-mining mode.

To let a worker request its own payout, the node operator must opt in:

```sh
parano1d \
  --mode extminer \
  --mining-key-file ~/.parano1d/mining.key \
  --allow-custom-coinbase
```

The worker can then use:

```sh
parano1d-miner \
  --key-file ~/.parano1d/mining.key \
  --coinbase o1...
```

Custom coinbase changes only the payout embedded before proof construction.
The worker still cannot modify the proved template.

The bearer credential is scoped to `getBlockTemplate` and `submitBlock`. It
cannot call wallet, node-control or general inspection methods.

## Separate pool operator host

Pools that keep accounting and payouts away from the wallet node can configure
a second, distinct credential:

```sh
umask 077
openssl rand -hex 32 > /secure/parano1d-operator.key

parano1d \
  --mode node \
  --rpc-listen 0.0.0.0:9601 \
  --operator-key-file /secure/parano1d-operator.key
```

The operator token authorizes bounded accounting, transaction and receipt lookup and verification, fee and send planning, `walletSend`, exact wallet consolidation, and submission of externally authorized raw transaction intents. The exact list is in [JSON-RPC authentication](../reference/rpc.md#authentication). It cannot obtain or submit mining templates, stop the node, scan, discover or change wallet addresses, enumerate unbounded wallet history or UTXOs, or call unlisted methods. The mining and operator tokens cannot be the same.

If one daemon serves both functions, run it in `extminer` mode and provide both distinct files. If the wallet daemon is separate, it needs only the operator credential. Prover nodes keep only their mining credentials.

Because `walletSend` carries spending authority, allow only the accounting host through the firewall and use a VPN or authenticated TLS or SSH tunnel. The node's HTTP listener does not encrypt bearer tokens.

## Template lifecycle

`getBlockTemplate` returns an opaque single-use ID, 16-field PoW schedule,
nonce index and target. The worker searches random, independent nonce ranges
and calls `submitBlock` with exactly 16 little-endian nonce bytes.

A template expires after 30 seconds. It is also invalidated by a canonical tip
change, successful submission or node-side cancellation. A stale result is
normal and the worker requests another template after its poll interval.

## Diagnose

Run:

```sh
parano1d-miner --check-hardware
```

If requests fail:

- `401 Unauthorized` means the token is absent or does not match;
- a custom coinbase error means the node did not enable it;
- repeated stale templates usually mean the node is receiving new tips or
  proof preparation exceeds the template lifecycle;
- no template means the node is not synchronized, lacks the peer quorum or is
  not in `extminer` mode.
