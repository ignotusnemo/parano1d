# Networking

Parano1d uses libp2p for peer identity, discovery, relay and synchronization.
The public network protocol is identified as:

```text
/noid/mainnet/860e70453390bf81/1
```

The default P2P listener is TCP `9600`. JSON-RPC is a separate local
administration interface on `127.0.0.1:9601`.

## Peer identity and consensus identity

Each node persists a libp2p Ed25519 peer identity. It authenticates network
sessions and gives the peer a stable ID across restart.

That identity has no consensus authority. It cannot spend a UTXO, sign a block
or influence proof verification. Wallet ownership, block validity and proof of
work use the binary consensus stack instead.

## Discovery

Nodes combine three discovery sources:

- built-in DNS seeds for initial public peers;
- Kademlia for ongoing peer discovery;
- mDNS for peers on the local network.

Successful peer addresses are persisted and reused. The peer store keeps up to
500 peers and limits the number of remembered addresses for any one peer.

GossipSub maintains a four-neighbour propagation mesh, while the automatic
topology manager targets eight ordinary neighbours for exact-object diversity
and failover. This is a connectivity floor, not a cap on the node's total peer
count: inbound, direct, LAN and relay-backed peers may increase it further. At
most four unselected incoming peers satisfy that floor, so each node still
selects at least four ordinary neighbours independently. DNS seeds provide the
first two paths; as stable ordinary peers become available, seed connections
are replaced without first dropping below the target. Discovery uses identity
jitter, one active lookup and exponential retry backoff. Seeds are therefore
bootstrap anchors, not a permanent exclusive topology.

Embedded seed names are resolved first through the operating system so scoped
VPN resolvers work, while the DNS multiaddress remains available for later
A/AAAA re-resolution. DNS records point to network endpoints, not chain state.
Changing software or resetting a node does not require changing its DNS name
if the public address remains the same.

## Gossip

GossipSub carries transaction intents and small header-first block
announcements. Bodies and recursive terminals are never required to share the
header control lane: they are pulled afterwards by exact content identity.
Gossip messages have a strict maximum size so a peer cannot turn ordinary
relay into unbounded allocation.

A transaction is relayed only after local mempool admission has verified its
canonical structure, authorization and current conflicts. Receiving gossip is
never equivalent to accepting consensus State.

For locally admitted transactions, GossipSub is supplemented by bounded direct
push. A node with at most eight connected peers pushes to all of them. Above
that size it pushes to a random fanout of at most four while GossipSub remains
the network-wide relay path. This gives a small network immediate first-hop
coverage without turning large-network propagation into all-peer broadcast.

## Request-response protocols

Typed exchanges serve:

- header batches;
- retained block bodies and recursive suffix-tip terminals;
- small snapshot headers, content-addressed manifest pages and State segments;
- recent mempool inventory and missing intents.

Direct catch-up requests ask for at most 512 headers at a time. Snapshot
header staging uses batches of up to 4,096 headers. Each batch is compressed
with zstd. Both the compressed input and decompressed output have strict size
limits; the output is at most 0.83 MiB of canonical 212-byte headers. Decoded
headers enter the existing validation and storage path unchanged.
Snapshot State is transferred as a small manifest header, bounded descriptor
pages and individually authenticated segments rather than as one unbounded
message. One immutable plan may obtain different exact objects from different
peers; losing a source does not discard already verified progress.

State transport advertises `/sync/segment/6` and `/sync/segment/5`.
Peers automatically negotiate one
version per exchange. Version 5 retains its original wire bytes. Version 6
uses zstd when it reduces the payload and can combine up to 64 small segments
within 64 KiB of canonical data; larger segments travel individually. Each
segment still passes its own immutable descriptor and root checks.

Matching local segments pass the same authentication and durable staging
before being reused. Root and length metadata are only lookup hints; corrupt
local bytes fall back to downloading. State keeps one network request in
flight, one staging worker and one buffered response. Both transport versions
share the existing serving limits and byte budgets; compressed input,
decompressed output and batch copies are admitted before allocation.

Mempool reconciliation requests at most 128 intents and 16 MiB per response.
A partial response can continue through one consumption-paced recovery lane,
using at most four selected sources. Requests to the same source are at least
30 seconds apart; timeouts, failed attempts and scan work are bounded.
Recovery stops at local capacity and does not poll idle seeds periodically.
An incoming connection cannot start arbitrary new recovery, but a previously
authorized recovery may continue over a surviving authenticated connection.
Peers without the optional continuation protocol use the legacy exchange.

Byte-identical gossip and direct deliveries are coalesced before consuming
duplicate ingress allowance. This is not a validity cache: ordinary local
admission remains required, and previously accepted entries absent from the
mempool can be reconsidered. Normal forwarding still follows successful
admission. Dead or disconnected sources do not hold the recovery lane forever.

Bootstrap selection is tied to the authenticated configured seed identity,
not just one socket. A reconnect or simultaneous cross-dial can preserve that
selection; replacement retires the remaining seed transport only after the
ordinary-peer handoff is stable. It does not let an arbitrary inbound peer
declare itself selected.

## Resource boundaries

Public networking is bounded at multiple layers:

- response byte budgets apply independently to inbound and outbound service;
- block and gossip message sizes are capped;
- State is segmented;
- peer addresses and peer-store entries are bounded;
- repeated invalid behavior is penalized;
- connection diversity is enforced by network group.

Outbound selection permits no more than two peers from one network group.
Inbound service permits at most 32 peer identities from one IP address and 96
connections from one network group. After the first 96 inbound connections,
the remaining capacity is reserved for groups that are not already well
represented; no such group may occupy more than eight of those reserved
positions. These limits accommodate shared VPN and carrier-NAT exits without
letting one hosting range fill every inbound slot.

They are not a substitute for a diverse public topology. Seed and mining
infrastructure should span independent networks and operators.

## Mining peer gate

Ordinary mining requires one authenticated peer. This prevents an unattended
node from extending an isolated private view merely because its network link
failed.

The gate is operational, not a vote. Peers do not approve the block and cannot
make an invalid transition acceptable. Once connected, the miner follows local
proof verification and cumulative-work consensus.

## Interface boundaries

P2P port `9600` serves public peers. RPC on `9601` includes wallet and
process-control methods. Local TCP loopback has owner access; remote mining
and operator tokens grant fixed, narrower method sets. Contract methods
require local owner access. HTTP bearer tokens do not encrypt traffic, so
remote RPC needs a private tunnel or protected TLS transport.

See [Configuration](../operate/configuration.md) for deployment settings and
[Synchronization](synchronization.md) for the data carried by sync protocols.

## Proof transport

The per-block terminal cap remains **1,100,000 bytes** for all three classes.
The one-time fork-origin exchange has a separate **48 MiB** response cap.
It authenticates the selected ancestry boundary. Subsequent recursive proofs
retain that binding. Contract openings
and authorization capsules travel with transaction intents under their own
bounds. [Files, ports and limits](../reference/files-and-ports.md) lists the
RPC, receipt and intent caps separately.
