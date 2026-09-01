# Mining

**Hashpower alone cannot produce blocks. Mining requires State; nonce search
begins only after the proof is complete.**

Proof of work in Parano1d orders transitions whose validity has already been
established. Before searching a nonce, a block producer must follow the
canonical chain, hold the current State, construct the exact next
transition and complete its recursive `HistoryStep`.

This makes the proving full node—not an individual hash worker—the unit of
independent block production.

![Proof-native block flow](../assets/architecture/proof-native-block-flow.svg)

## What the node and worker do

A mining node owns the block. It:

- follows and independently validates the canonical chain;
- verifies transaction intents before they enter its mempool;
- selects a non-conflicting transaction set;
- fixes the payout, fees, slot writes and post-State root;
- proves the nonce-independent block and preceding terminal;
- validates the winning nonce;
- commits and broadcasts the complete `{block, HistoryStep terminal}` bundle.

Nonce search may run inside that process or in `parano1d-miner`. An external
worker has a much narrower role:

- receive one immutable Poseidon2b header schedule and target;
- search independent values of its 128-bit nonce;
- return a candidate nonce to the node.

The worker does not receive the block body, State witness or `HistoryStep`
witness. It cannot replace transactions, alter the State root or modify a
template after proof construction.

## One block attempt

Block production proceeds in this order:

1. The node waits until it is synchronized and has the required authenticated
   peer quorum.
2. It reads its canonical tip, current State and admissible mempool intents.
3. It selects the B25 or B255 proof class and fixes every semantic field of the
   candidate block except its nonce.
4. It computes the exact slot writes and resulting UTXO root.
5. It proves the new `HistoryStep`, including recursive continuity from the
   preceding terminal.
6. The completed proof fixes one immutable mining template.
7. The internal miner or an external worker searches the Poseidon2b nonce.
8. The node checks the nonce, seals the prepared terminal, commits the block
   atomically and announces it to peers.

A new canonical tip makes unfinished work stale. The node discards that attempt
and starts from the new State; it never moves an old proof onto a different
parent or transaction set.

Peers accept the result only after independently checking the parent,
`HistoryStep`, PoW target and every consensus commitment. Cumulative work
chooses between valid competing chains.

## Two mining modes

| Mode | Proof construction | Nonce search | Best fit |
|---|---|---|---|
| Internal | Core node | Core node | GUI wallet, solo miner, one server |
| External | Core node | `parano1d-miner` | Separate CPU worker, private mining network or pool |

Both modes use the same consensus rules and produce the same blocks. External
mining moves only nonce search across the RPC boundary.

An ordinary `--mode node` process validates and relays blocks but does not
construct mining templates.

## Mine from the GUI wallet

The native wallet supervises its own full node. Open **Mining** with `F5`,
choose the CPU thread budget and select **Start mining**.

Mining becomes available after the node is synchronized and connected to at
least one authenticated peer. The active wallet address receives newly
constructed payouts. Changing the active address affects the next template;
an existing immutable template keeps its original payout.

The page reports the selected CPU backend, B25/B255 readiness, current mining
state and locally found blocks. See
[Mining in the wallet](../wallet/mining.md) for shutdown behavior and the mined
block table.

## Run the internal Core miner

Check the actual host before creating node data:

```sh
parano1d --check-hardware
```

Start Core with its built-in miner:

```sh
parano1d --mode miner --cpu-threads 12
```

Omit `--cpu-threads` to use every logical CPU visible to the process. When no
explicit payout is configured, Core uses the active address in its local
wallet. A separate canonical bech32m payout can be fixed with:

```sh
parano1d --mode miner --miner-address o1...
```

Watch readiness and chain progress from another terminal:

```sh
parano1d-cli status
parano1d-cli peers
parano1d-cli mining
```

Core waits rather than mining an isolated local view when it is unsynchronized
or has no authenticated peer. The complete server and systemd
procedure is in [Internal mining](../operate/internal-mining.md).

## Run an external worker

Start a node that owns and proves external-mining templates:

```sh
parano1d \
  --mode extminer \
  --mining-key-file ~/.parano1d/mining.key
```

Run the worker against its loopback RPC endpoint:

```sh
parano1d-miner \
  --rpc http://127.0.0.1:9601 \
  --key-file ~/.parano1d/mining.key \
  --threads 12
```

The node prepares a complete proof before returning a template. The worker
searches its nonce and submits only the result. Templates are single-use,
expire after 30 seconds and become stale immediately after a competing tip is
accepted.

A remote worker should connect through an authenticated private network or a
TLS endpoint with firewall restrictions. A bearer token authenticates the
worker but does not encrypt plain HTTP. The token authorizes only
`getBlockTemplate` and `submitBlock`; it cannot access wallet or node-control
methods. The legacy `--mining-key` and `--key` arguments remain compatible,
but protected key files avoid exposing the token in process arguments.

By default, the node controls the payout. Allowing authenticated workers to
request their own payout is an explicit operator decision. The full remote
configuration and trust boundary are documented in
[External miner](../operate/external-miner.md).

## CPU and proof capacity

The production instruction floor is:

| Architecture | Required instructions |
|---|---|
| x86-64 | SSE4.1 and PCLMULQDQ |
| ARM64 | NEON and PMULL |

Wider kernels are selected at runtime when the host exposes them. The hardware
check establishes that the production backend can run; it does not guarantee
competitive mining performance.

Every mining process begins with the B25 proof class. B255 is used only when
measured complete preparation time supports the larger relation. Both classes
prove the same consensus statement:

| Class | Relation | Effective page positions |
|---|---|---:|
| B25 | `m=22` | up to 25 |
| B255 | `m=24` | up to 255 |

Proof construction and PoW are ordered all-core phases sharing one thread
budget. They are not two competing all-core jobs. On a public host, leaving
some CPU capacity outside `--cpu-threads` keeps the operating
system and peer service responsive.

The network targets a 20-second mean block interval. This is not a deadline:
individual blocks may arrive sooner or much later. Proof latency still matters
because a candidate becomes stale when another miner advances the tip. Measure
the complete B25 preparation path on the intended machine rather than judging
it only by CPU model or advertised vCPU count.

See [Hardware and capacity](../operate/hardware.md) and
[Performance measurements](../reference/performance.md) for the production
floor and published reference timings.

## Difficulty, rewards and confirmations

ASERT adjusts the Poseidon2b target against the complete interval between
accepted blocks. Proof preparation, nonce search and propagation share that
20-second mean target.
The chain with the greatest cumulative valid work wins; an equal-work tie uses
the canonical block-hash tie-break.

The current reward follows the active State level and is displayed by:

```sh
parano1d-cli mining
```

During the three-year development allocation, the miner receives 90% of newly
issued block rewards. Claimable transaction fees also belong to the miner
after the consensus State-growth burn. After the allocation ends, 100% of each
new block reward goes to the miner.

A locally found block is not an immediate final balance. Its confirmation depth
increases as valid descendants are accepted, and a shallow higher-work reorg
can replace it inside the retained competition window.

## Mining and decentralization

An autonomous miner cannot operate from hashpower alone. Its node must remain
current, validate incoming work, construct and prove the next exact State transition before
any nonce engine receives useful work. When that node accepts inbound P2P
connections, the same infrastructure also relays transactions and blocks and
serves synchronization data.

External workers and pools remain possible: one proving node can serve more
than one nonce worker. Parano1d therefore does not claim that specialized
hardware is impossible. Its stronger and narrower property is that
specialized hashpower cannot independently originate a block or compensate for
an incapable proof node.

For the exact header relation, continue with
[Proof of work](../protocol/proof-of-work.md). For the implementation pipeline,
read [Block production](../architecture/mining.md).
