# Command-line interfaces

The Core archive contains three executables:

| Executable | Role |
|---|---|
| `parano1d` | Full node, wallet backend and optional internal proof/mining pipeline |
| `parano1d-cli` | Thin JSON-RPC client for a running node |
| `parano1d-miner` | Separate Poseidon2b nonce-search worker |

## Core daemon

Run an ordinary node with no mode argument:

```sh
parano1d
```

Public daemon options are:

| Option | Meaning |
|---|---|
| `-c, --config FILE` | TOML configuration path |
| `--mode node` | Ordinary non-mining node |
| `--mode miner` | Node with internal proof and PoW pipeline |
| `--mode extminer` | Node-owned proof pipeline with external nonce worker |
| `--miner` | Shorthand for `--mode miner` |
| `--extminer` | Shorthand for `--mode extminer` |
| `--miner-address ADDRESS` | Mining payout address; active wallet owner is the default |
| `--cpu-threads N` | Shared internal-miner thread budget |
| `--data-dir PATH` | Chain, wallet and runtime data directory |
| `--p2p-listen HOST:PORT` | P2P listener; default `0.0.0.0:9600` |
| `--rpc-listen HOST:PORT` | JSON-RPC listener; default `127.0.0.1:9601` |
| `--seed ENDPOINT` | Add a bootstrap endpoint; repeatable |
| `--log LEVEL` | Tracing filter such as `error`, `warn`, `info` or `debug` |
| `--mining-key TOKEN` | External-mining bearer token; retained for compatibility |
| `--mining-key-file FILE` | Read the external-mining bearer token from an owner-only file |
| `--operator-key TOKEN` | Separate bearer token for the fixed pool accounting/payout RPC scope |
| `--operator-key-file FILE` | Read the pool operator token from an owner-only file |
| `--allow-custom-coinbase` | Permit an authenticated external worker to request its payout |
| `--purge-state` | Clear the complete chain database and synchronize it again from peers |
| `--check-hardware` | Report production CPU support and exit without touching node data |

Mode-specific options are rejected when they cannot apply. `--cpu-threads`
belongs to internal miner mode. External-miner mode requires either
`--mining-key` or `--mining-key-file`; `--allow-custom-coinbase` requires
external-miner mode and a configured key.

`--purge-state` is a repair and upgrade tool, not a routine start option. It
removes headers, chain indexes, retained blocks, undo data and Live State from
the chain database. Wallet files, receipts and peer identity are stored
separately and remain; the node then authenticates the chain and State again
from peers.

Examples:

```sh
# Ordinary node
parano1d --data-dir ~/.parano1d/data

# Internal miner using 12 logical CPUs
parano1d --mode miner --cpu-threads 12

# Node with a local external nonce worker
parano1d --mode extminer --mining-key-file ~/.parano1d/mining.key
```

Keep RPC on loopback unless it is protected by a private or authenticated transport. A bearer key authenticates requests but does not encrypt them. The operator credential can authorize `walletSend`; prefer `--operator-key-file`, use a distinct token from the mining credential, and firewall the listener. Core refuses to start a non-loopback RPC listener unless at least one scoped credential is configured. The GUI and CLI may connect from the actual TCP loopback address without a key even when scoped credentials are configured. RPC supports HTTP only and rejects WebSocket upgrades.

## External miner

`parano1d-miner` requests an already-proved, immutable template and searches
only its 128-bit nonce.

| Option | Default | Meaning |
|---|---|---|
| `--rpc URL` | `http://127.0.0.1:9601` | Node JSON-RPC endpoint |
| `--key TOKEN` | — | Bearer token matching the node; retained for compatibility |
| `--key-file FILE` | — | Read the bearer token from an owner-only file |
| `--threads N` | `0` | PoW threads; zero uses every visible logical CPU |
| `--coinbase ADDRESS` | — | Custom `o1…` payout when the node explicitly permits it |
| `--poll-ms MS` | `500` | Delay before requesting another template |
| `--log LEVEL` | `info` | Worker log filter |
| `--check-hardware` | — | Report production CPU support and exit |

Typical local use:

```sh
parano1d-miner \
  --rpc http://127.0.0.1:9601 \
  --key-file ~/.parano1d/mining.key \
  --threads 12
```

See [External miner](../operate/external-miner.md) for the remote transport and
custom-payout boundaries.

## Node client

`parano1d-cli` is a thin client for a running Core node. It holds no separate key
and performs wallet operations through local JSON-RPC.

### Global options

```text
-r, --rpc URL   RPC endpoint
-j, --json      raw JSON output
```

The default endpoint is `http://127.0.0.1:9601`. Environment variable
`NOID_RPC` changes it. `--rpc` takes precedence.

Amounts entered by CLI wallet commands are in NOID with up to six decimal
places:

```text
1 NOID = 1,000,000 μNOID
```

### Node and chain

| Command | Arguments | Result |
|---|---|---|
| `status` | — | Tip, hash, difficulty and active State summary |
| `block-hash` | `HEIGHT` | Permanent nonce-bearing block ID |
| `block-header` | `HEIGHT` | Structured permanent header |
| `header` | `HEIGHT` | Raw canonical 212-byte header hex |
| `block` | `HEIGHT` | Raw full block hex when retained |
| `history-step-terminal` | — | Current local terminal hex |
| `tx` | `TXID` | Permanent confirmation location |
| `slot` | `INDEX` | Current slot contents |
| `utxos-of` | `o1…` | Current UTXOs owned by an address |
| `state` | — | Capacity, occupancy and encoded State size |
| `epoch` | — | Current 144-block user transaction anchor |

Examples:

```sh
parano1d-cli status
parano1d-cli block-header 420
parano1d-cli block 420
parano1d-cli slot 9700063
parano1d-cli utxos-of o1...
```

`block` returns data only inside the 18-block body-retention window. `header`
and `block-header` remain available for every canonical height.

### Network and mining

| Command | Options | Result |
|---|---|---|
| `peers` | — | Connected peer count |
| `mining` | — | Difficulty, next reward and mining state |
| `block-template` | `--miner-addr o1…` | Node-owned external mining template |
| `submit-block` | `TEMPLATE_ID NONCE_HEX` | Submit one 16-byte little-endian nonce |

The external-mining commands are low-level. `parano1d-miner` handles template
refresh and nonce encoding automatically.

### Fees and mempool

```sh
parano1d-cli estimate-fee 2 --inputs 1
parano1d-cli mempool
parano1d-cli mempool-tx TXID
```

`estimate-fee` reports the current node-accepted minimum for the declared live
input and output counts. Mempool rows are logical `PagedSpend` intents, not
individual physical pages.

### Address validation

```sh
parano1d-cli validate o1...
```

The command reports validity, canonical bech32m form and raw 32-byte payload.

### Wallet addresses

```sh
parano1d-cli address
parano1d-cli address --list
parano1d-cli address --new
parano1d-cli address --index 3
parano1d-cli address --use 3
```

`--new`, `--index` and `--use` are mutually exclusive actions. A generated
address is inactive until selected. Sends use only the active owner's UTXOs
and return change to that owner.

### Balance and UTXOs

```sh
parano1d-cli balance
parano1d-cli utxos
parano1d-cli scan
```

`balance` separates confirmed, reserved outbound, pending incoming and
spendable values. `scan` reloads the active owner from the verified persistent
owner index.

### Send

Preview:

```sh
parano1d-cli send o1... 10.5 --dry-run
```

Submit with automatic fee:

```sh
parano1d-cli send o1... 10.5
```

Specify an exact fee in NOID only when needed:

```sh
parano1d-cli send o1... 10.5 --fee 0.012
```

The returned ID names the complete logical spend. Automatic fee selection is
recommended because occupancy and relay floor can change.

### History and receipts

```sh
parano1d-cli history
parano1d-cli history --last 20
parano1d-cli history --address o1...
```

Export a confirmed outgoing receipt:

```sh
parano1d-cli receipt TXID > receipt.hex
```

Verify it:

```sh
parano1d-cli verify "$(tr -d '\n' < receipt.hex)"
```

Receipt export works only for a locally saved different-owner payment.

### Stop

```sh
parano1d-cli stop
```

This requests graceful daemon shutdown. It is equivalent to the GUI's normal
exit path, not a process kill.

### Scripting

Use `--json` and check the process exit status:

```sh
height="$(
  parano1d-cli --json status |
    jq -er '.height'
)"
```

Human-readable output and colors are presentation interfaces. Scripts should
consume JSON.
