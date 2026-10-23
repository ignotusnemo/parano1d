# Mining architecture

**Hashpower alone cannot produce blocks. Mining requires State; nonce search
begins only after the proof is complete.**
The block producer must hold the current State and establish the exact next
transition before nonce search begins. An independent miner is therefore a
proving full node backed by hashpower, not a stateless hashing endpoint.

Mining has two ordered phases:

1. select transactions, construct the State transition and prove the complete
   nonce-independent block;
2. search the 128-bit nonce of the fixed Poseidon2b header.

This order prevents proof of work from being spent on a block whose transition
has not yet been established.

## Template construction

The node starts from its canonical tip and current mempool. It selects
non-conflicting logical transactions by fee rate while respecting State,
segment and proof-class limits. It then:

- computes coinbase and any scheduled system payout;
- assigns fresh output creation identifiers;
- derives canonical slot writes;
- computes transaction and post-State roots;
- builds the `HistoryStep` public input;
- proves the new terminal.

System-mint slot selection prefers not to occupy outputs reserved by other
pending transactions. This is a bounded local preference, not a veto. If no
alternative is found, the previous valid choice is used. Selected transactions
remain strictly protected; fund recipients, payout amounts and schedules do
not change.

Everything except the header nonce is now immutable.

<a id="small-and-large"></a>

## Small, Large and Native

The bank has three jointly authenticated classes:

| Class | Pages | Live inputs | Calls |
| --- | ---: | ---: | ---: |
| Small, m23 | 63 | 504 | 63 |
| Large, m24 | 206 | 504 | 63 |
| Native, m24 | 63 | 504 | 63 |

Small covers ordinary NOID payments and ABI 3 calls. Native adds token,
launchpad, DEX and NFT operations while also admitting ordinary payments and
ABI 3 calls. During native execution the node considers Small and Native
automatically. `--v2-large-blocks` additionally permits Large for both internal
mining and external templates. The producer selects the candidate with the
greatest claimable fees and builds one proof. Equal fees retain Small when it
is eligible. Every node verifies all three classes.

Calls share page and input budgets with payments. Large can fit 63 calls plus
143 one-page payments, within the 504-input bound. Primary coinbase is separate;
an extra mandatory system record uses one effective page. ABI 3 programs use the same
interpreter in every class. Query `getContractProtocol` for installed budgets.

ASERT targets the complete 30-second mean interval: proving, nonce search and
propagation all consume it. Benchmark the complete preparation path on the
actual host. [Performance](../reference/performance.md) describes the matched
measurement scope. Record the complete path and its hardware conditions.

## CPU scheduling

The internal miner uses one shared CPU pool across proof construction and
nonce search. It does not run two unrelated all-core jobs at once.

Local wallet work has priority. When a user sends or consolidates while mining
is active, the node pauses or yields mining CPU work at the local boundary,
completes transaction authorization and submission, then continues mining.
No network rule, peer priority or global fee policy changes.

## Refresh policy

Templates are rebuilt on events that change useful work:

- a new canonical tip;
- a mining payout-address change;
- the first transaction entering a coinbase-only template;
- invalidation of selected transactions.

The default fallback heartbeat is five target intervals, or 150 seconds. The events above normally refresh work sooner.
Already proved templates remain bound to their original payout and transaction
set; they are not mutated after proof construction.

## Internal miner

The internal miner runs inside the node process. The node owns transaction
selection, proof construction, PoW and block submission. CPU thread count and
payout address can be controlled through Core and its local RPC.

Mining starts only when the node is synchronized and has at least one
authenticated peer. A locally found block is sealed, committed and announced
under the same consensus rules as a received block. Its commit path reuses the
exact locally proved State transition instead of verifying the same proof
again. Received blocks still undergo proof verification.

## External miner

The external miner moves only nonce search out of the node. It requests an
opaque, single-use template containing:

- template identifier;
- exact 16-field Poseidon2b PoW schedule;
- target;
- expiry and display metadata.

It returns one little-endian 128-bit nonce. The node verifies the nonce against
the still-live template, seals the already-proved block and invalidates the
template. External templates expire after 30 seconds and cannot be replayed
after a tip change or successful submission.

The external worker never receives authority to replace transactions, alter
State, change fees or recompute coinbase. Custom coinbase use requires both an
explicit node setting and a bearer key.

## Fork choice

Mining extends the highest-cumulative-work valid chain. Equal-work candidates
use the lexicographically smaller block hash as a deterministic tie-break.
Candidates that would replace the hard-finalized prefix are not eligible.

For deployment, see [Internal mining](../operate/internal-mining.md) or
[External miner](../operate/external-miner.md). The exact nonce relation is in
[Proof of work](../protocol/proof-of-work.md).
