# Testing

Parano1d uses three layers of tests: crate-level invariants, cross-crate
release tests and fresh-process live scenarios.

## Fast checks

Run before a focused change:

```sh
cargo fmt --all -- --check
cargo check --release --locked --workspace --all-targets
cargo test --release --locked -p CHANGED_CRATE
```

For protocol code, include direct dependants. A transaction change commonly
requires at least:

```sh
cargo test --release --locked \
  -p noid_tx \
  -p noid_chain \
  -p noid_mempool \
  -p noid_miner \
  -p noid_rpc \
  -p noid_node
```

## Proof kernels

Production kernel tests should run in release mode:

```sh
cargo test --locked --release \
  -p noid_core \
  -p noid_poseidon2b \
  -p noid-ivc-core
```

On x86-64, force the production floor:

```sh
NOID_CPU_BACKEND=pclmul \
  cargo test --locked --release \
  -p noid_core -p noid_poseidon2b -p noid-ivc-core
```

The scalar backend is used only for differential checking:

```sh
NOID_CPU_BACKEND=scalar \
  cargo test --locked --release \
  -p noid_core -p noid_poseidon2b
```

## Release gates

`scripts/build_release.sh` authenticates and embeds the release matrix packs
and smoke-tests the native executables. Run source checks and tests separately
before packaging. The package smoke tests cover:

- hardware preflight;
- node help and startup boundary;
- CLI;
- external miner;
- packaged GUI self-check.

Do not treat a debug binary or pack-free development node as a block-production
test.

## Live scenarios

Live scripts create fresh data directories under `target/live-tests`. They
exercise real processes, RPC, P2P, MDBX and the production proof path.

| Scenario | Coverage |
|---|---|
| `live_cli_wallet_scenarios.py` | Three-node CLI, relay, address, send, history and receipt lifecycle |
| `live_single_transaction_scenario.py` | Wallet → mempool → miner → canonical block |
| `live_multi_transaction_mempool_scenario.py` | Three non-conflicting intents and relay |
| `live_large_mempool_single_miner_scenario.py` | 128 intents drained under the fixture’s active class |
| `live_large_mempool_two_miners_scenario.py` | Large mempool under miner competition |
| `live_two_miner_fork_reorg_scenario.py` | Competing children and shallow reorg |
| `live_connected_miner_restart_sync_scenario.py` | Restarting miners and stale-parent prevention |
| `live_mining_peer_gate_scenario.py` | Ordinary peer quorum |
| `live_sync_scenarios.py` | Fresh, 5-block and 19-block sync boundaries |
| `live_incremental_snapshot_scenario.py` | Full plus incremental snapshot publication |
| `live_sync_announced_tip_scenario.py` | Catch-up bounded by announced tip |
| `live_state_restart_scenario.py` | Compact state restart and first new block |
| `live_state_slot_lifecycle_scenario.py` | Slot clear, reuse, density and restart |
| `live_receipt_lifecycle_scenario.py` | Receipt save, tamper, restart and pruned-body verification |
| `live_wallet_active_address_scenario.py` | Generate, fund, activate and persist owners |
| `live_wallet_mining_payout_switch_scenario.py` | Atomic payout-owner switch |
| `live_wallet_receive_online_scenario.py` | Incremental online recipient updates |
| `live_wallet_receive_offline_shallow_scenario.py` | Recipient recovery through retained blocks |
| `live_wallet_receive_offline_snapshot_scenario.py` | Recipient recovery through snapshot sync |
| `live_slot_mempool_wallet_scenarios.py` | Salted hints, multi-node sends and convergence |
| `live_p2p_identity_handshake_scenario.py` | Persistent peer ID and symmetric handshake |
| `live_p2p_fan_in_scenario.py` | Concurrent inbound handshake load |
| `live_p2p_inbound_sybil_scenario.py` | Per-IP inbound limit |
| `live_p2p_outbound_diversity_scenario.py` | Outbound network-group diversity |
| `live_p2p_mesh_block_scenario.py` | Block relay beyond the preferred mesh |

Each script documents its environment knobs and binary expectations at the top.
Run it from the repository root:

```sh
python3 scripts/live_two_miner_fork_reorg_scenario.py
```

## Boundary changes

Changes near finality, epochs or State expansion require explicit boundary
vectors, not only a long-running happy path. Cover:

- heights 143, 144 and 145 for transaction anchors;
- 17- and 18-block fork depths;
- 18- and 19-block synchronization gaps;
- finalized expansion windows with 9/9 and 10/8 occupancy;
- restart with the complete 36-header expansion lookback;
- payout boundaries and the final allocation height;
- State expansion from one `log_slots` tier to the next;
- shared-path terminal round trips, malformed encodings and decode caps;
- mempool count/byte pressure at 50% and 80%, empty-pool reset and Auto retries;
- partial mempool recovery, duplicate deliveries and disconnected sources;
- Small/Large selection and reserved system-mint slots, including all-reserved fallback.

Tests should use isolated data directories. They may use different ports to run
concurrently, but must not mutate fixtures or production data.

## V2 qualification

The `live_v2_*` scripts use isolated, loopback-only networks and binaries with
early test heights. Read each script's required matrix bank, environment and
stopped-fixture inputs before running it. Mainnet source uses H210537; a pack
for an early test height cannot be used in a mainnet build.

| Script | Coverage |
| --- | --- |
| `live_v2_contract_scenario.py` | Contract programs, both authorities, pruning and restart |
| `live_v2_capacity_scenario.py` | Full Small/Large payments and calls; Small after Large |
| `live_v2_boundary_reorg_scenario.py` | Fork boundary, shallow competing ancestry and recovery |
| `live_v2_parent_target_scenario.py` | Equal targets for v2 siblings and three-node convergence after a same-height fork |
| `live_v2_retired_sync_scenario.py` | Cold synchronization without embedded legacy matrices |
| `live_v2_retired_mining_scenario.py` | Continuing production after legacy-matrix retirement |
| `live_v2_contract_discovery_scenario.py` | Related contract states and retained receipt discovery |
| `live_v2_shared_receipts_scenario.py` | Shared terminal storage and receipt integrity |
| `live_v2_contract_wallet_scenario.py` | Two wallets, both parties, offline gaps and merging after pruning |

Boundary vectors also cover H−1/H/H+1, both legacy predecessor classes, mixed
ASERT intervals, annual issuance steps, contract deadlines, checked u64
arithmetic and competing spends. Full workloads share the page, input and call
budgets. Validate the mainnet bank separately from the early-height bank;
[performance](../reference/performance.md) identifies measured artifacts.
