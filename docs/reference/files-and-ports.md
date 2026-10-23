# Files, ports and limits

## Default paths

| Path | Purpose | Authority |
|---|---|---|
| `~/.parano1d/parano1d.toml` | Core configuration | Operator |
| `~/.parano1d/gui-settings.json` | GUI preferences | Local UI |
| `~/.parano1d/data/` | Default Core and GUI node data | Consensus data |
| `DATA_DIR/wallet.key` | 256-bit wallet master secret | Spending authority |
| `DATA_DIR/wallet.receipts` | Saved outgoing receipts | Local payment evidence |
| `DATA_DIR/wallet.labels` | Persistent address labels | Local display only |
| `DATA_DIR/wallet.history` | Local wallet history | Local presentation |
| `DATA_DIR/wallet.native-pending` | Restartable native submission activity | Local operation tracking |
| `DATA_DIR/native-media/` | Bounded cached metadata and images | Verified display data |
| `DATA_DIR/native-media/queue/` | Prepared publication records | Pending asset uploads |
| `DATA_DIR/p2p_identity.key` | Stable libp2p Ed25519 identity | Network identity only |
| `DATA_DIR/peers.json` | Successful public outbound peers | Discovery hint |
| `DATA_DIR/history-step-cache/` | Derived local proof-matrix cache | Rebuildable |
| `DATA_DIR/snapshot-staging/` | Incoming snapshot scratch data | Never canonical |
| `DATA_DIR/parano1d-gui.toml` | GUI-owned node configuration | Private node |
| `DATA_DIR/parano1d-node.log` | GUI-owned node log | Diagnostics |

On Windows, `~` means the user profile directory.

`wallet.key` and `p2p_identity.key` are owner-only files on Unix. The first
controls funds; the second does not.

## Wallet artifact storage

`wallet.receipts` and `wallet.history` use checksummed local journals. A normal
save appends only changed receipts or the changed history suffix. Periodic
atomic snapshots compact obsolete records. The exported payment receipt and
all consensus formats are unchanged.

Existing JSON artifacts remain readable and migrate on their first save. The
original files are preserved as `wallet.receipts.legacy` and
`wallet.history.legacy`. These are pre-migration recovery copies, not current
backups. A conflicting existing recovery copy is never overwritten.

A JSON-only reader cannot read the journal format. Individual exported receipts
remain independent of this storage encoding. A master-secret backup alone does
not restore old receipts.

On startup, complete frames must pass checksum and schema checks. A partial
final append is reported and ignored without discarding earlier committed
frames. Missing initial snapshots and corrupted complete frames fail startup.
The next successful write repairs an incomplete tail. These checks protect
local storage integrity, not consensus validity or authorization to spend.

## Ports

| Port | Bind | Use | Public |
|---:|---|---|---|
| TCP 9600 | `0.0.0.0` | libp2p | Yes |
| TCP 9601 | `127.0.0.1` | JSON-RPC | No |

Remote external mining may use RPC only through a protected private or TLS
transport. A bearer token authenticates requests but does not encrypt them.

## Network identity

| Item | Value |
|---|---|
| Network | `mainnet` |
| Genesis block ID | `860e70453390bf815718e933aa4927167a13d098b0151391eefd722ee1add610` |
| Network magic | `NOID` |
| libp2p protocol | `/noid/mainnet/860e70453390bf81/1` |
| Transaction and block gossip | GossipSub |
| Discovery | DNS seeds, Kademlia, mDNS |

## Retention

| Data | Window |
|---|---:|
| Headers | Permanent |
| Canonical block bodies | 42 |
| Reorganizable suffix | 18 |
| Maximum reorganization | 17 |
| Undo records | 36 |
| Transaction epoch | 144 |

Receipts preserve payment-specific inclusion evidence outside body retention.

## Local resource limits

| Resource | Limit |
|---|---:|
| Mempool logical transactions | 1,024 |
| Mempool intent bytes | 384 MiB |
| Mempool-sync response | 128 intents / 16 MiB |
| Orphan accepted bundles | 36 / 128 MiB |
| Peer-store entries | 500 |
| Addresses per stored peer | 8 |
| Automatic topology target | 8 ordinary peer identities |
| Established inbound transports | 128 |
| Established outbound transports | 64 |
| Pending inbound / outbound transports | 64 / 32 |
| Established transports per peer identity | 2 |
| Public outbound peers per network group | 2 |
| Public inbound peer identities per IP | 32 |
| Public inbound connections per network group | 96 |
| Direct-sync header request | 512 headers |
| Header protocol batch cap | 4,096 headers |
| Concurrent snapshot generation tasks | 1 |
| Unleased snapshot generations retained | 2 |
| Snapshot export lease idle lifetime | 15 minutes |
| Snapshot State segments in flight | 8 |
| State-segment request correlation entries | 64 |
| External template lifetime after proof preparation | 30 seconds |

## RPC bounds

| Operation | Bound |
|---|---:|
| State atlas | 256 buckets |
| Slot hints returned | 256 |
| Recent-transaction page | 32 rows |
| Receipt page | 50 rows |
| Mined-block page | 50 rows |
| Imported address discovery | 20 candidates |
| Interactive consolidation | 64 inputs |

## Contract artifacts and transport

| Artifact | Location and purpose |
| --- | --- |
| `wallet.contracts.json` | GUI wallet directory; public contract library and local names |
| `contract-activity/` | GUI wallet directory; saved local operations |
| `objects/` | Node wallet directory; tracked openings, states and receipts |
| `objects/terminals/` | Shared authenticated terminals referenced by local receipts |

Back up these files with the wallet secret. A key can recover authority, but a
hash commitment cannot reconstruct lost public program terms or old receipts.
Keep the objects directory together so shared terminal references remain usable.

| Bound | Value |
| --- | ---: |
| Recursive block terminal | 1,100,000 bytes |
| One-time fork-origin response | 48 MiB |
| Ordinary payment receipt | 128 KiB |
| Contract receipt | 1,110,624 bytes |
| RPC HTTP request body | 2,237,632 bytes |
| Contract instance query | 1…256 rows |
| Saved contract states or receipts per RPC page | 1…64 rows |
| Recent operations displayed by GUI | 256 |

The GUI limit bounds the displayed list; retained receipts remain in storage.
At 30 seconds, the 144-block epoch is nominally 72 minutes, the 18-block
finality window 9 minutes, and body/undo retention 21/18 minutes.
