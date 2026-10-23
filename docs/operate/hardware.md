# Hardware and capacity

Parano1d does not make chain age a permanent execution requirement, but a
node still needs enough CPU for proof verification, enough memory for bounded
network work and enough disk for the current Live State. Check the actual
machine exposed to the process; a provider's physical CPU model is not proof
that a virtual guest receives the required instructions.

## Production instruction floor

A production binary accepts either:

| Architecture | Required instructions |
|---|---|
| x86-64 | SSE4.1 and PCLMULQDQ |
| ARM64 | NEON and PMULL |

The scalar implementation is a test oracle, not a production fallback. An
unsupported host exits before opening the wallet or chain database.

Run the preflight on the intended host:

```sh
parano1d --check-hardware
parano1d-miner --check-hardware
```

A successful node report ends with:

```text
NODE READY
```

The report also names the selected runtime backend. Runtime dispatch chooses
`pclmul`, `avx2+vpclmul` or `avx512bw+vpclmul` on x86-64 and `neon+pmull` on
ARM64.

## Virtual machines

Some hypervisors mask PCLMULQDQ or advertise a generic legacy CPU even when
the physical host is newer. Before committing to a virtual server:

1. confirm that the guest is 64-bit;
2. request host-passthrough or a modern virtual CPU profile when available;
3. boot the exact plan and run `--check-hardware`;
4. reject the plan if the process reports `CPU UNSUPPORTED`.

On Linux x86-64, the relevant guest-visible flags can be inspected with:

```sh
grep -m1 '^flags' /proc/cpuinfo \
  | tr ' ' '\n' \
  | grep -E '^(sse4_1|pclmulqdq|avx2|vpclmulqdq|avx512)'
```

The production preflight remains authoritative because it checks the same
runtime path the node will use.

## Measured capacity

The receiver qualification used four CPU cores, 8 GiB RAM, no swap and
PCLMUL. Full Small and Large workloads completed with a 1.65 GiB receiver
peak in that scenario. Size the service with room for traffic, State growth,
wallet work and snapshot staging. The [measurements](../reference/performance.md)
separate preparation, verification and application and state each workload.

Block producers use server resources for proof construction and nonce search.
Small m23 is the default class; Large m24 requires `--v2-large-blocks`.
Size producer memory and CPU capacity for the intended block workload.
Seed and verification nodes verify received proofs. Their four-CPU receiver
qualification applies to verification service sizing.
CPU generation, available instructions, memory bandwidth and actual scheduler
quota all matter. Use SSD or NVMe storage and monitor free space.

The Native class also uses m24 and carries native financial operations
within its authenticated resource bounds. `getNativeProtocol` reports its
capacities; native activity shares the selected block's page and State-action
budgets with payments and contract calls. See [Native finance](../protocol/native-finance.md).

## Memory behavior

The implementation bounds major untrusted pools:

- at most 1,024 mempool transactions and 384 MiB of serialized intents;
- at most 36 retained orphan bundles and 128 MiB of their encoded bytes;
- one authenticated snapshot segment is decoded at a time; ordinary segments
  keep the 8 MiB transport cap, while native segments additionally carry their
  bounded typed-opening and definition closure;
- snapshot payload work is serialized;
- the recent complete-block and undo windows are fixed.

Total RSS also includes proof matrices, proving workspaces, database pages,
networking and operating-system overhead. Leave headroom and do not configure a
service limit equal to the observed idle RSS.

At a 65,536-slot segment, the native segment ceiling is 21,889,045 bytes
(about 20.88 MiB): sparse slot records plus the fixed native framing and at
most two 140-byte openings with their length fields per slot. The decoder
checks lengths and the complete slot/definition correspondence before
installation. This is a synchronization message bound, separate from the
proof class's working memory.

Internal mining uses one shared thread budget for proof construction and nonce
search. Set `--cpu-threads` to the logical CPUs actually assigned to the
service, not the physical host's advertised total.

## Disk behavior

There is no honest fixed disk figure for the lifetime of a node. Persistent
storage contains:

- permanent compact headers;
- the exact current sparse UTXO State and owner index;
- the latest 42 canonical block bodies;
- 36 blocks of State undo data;
- peer identity and peer store;
- proof cache and temporary snapshot staging;
- wallet keys, metadata and receipts when used.

Historical transaction bodies do not accumulate forever. Current live UTXOs
do: disk use follows State occupancy and the distribution of occupied
segments. MDBX grows in 64 MiB steps as needed.

Monitor the real path:

```sh
du -sh ~/.parano1d/data
parano1d-cli state
```

Snapshot synchronization requires temporary space for a complete candidate
State before atomic installation. Keep enough free disk for the installed
State plus one staged replacement and normal database growth.

## Network

Allow persistent outbound TCP connections and, for a public node, inbound TCP
`9600`. A 100 Mbit/s unmetered connection is a sensible baseline. Latency is
less important than stability and the absence of aggressive connection or
traffic caps.

RPC on TCP `9601` is an administrative interface. Keep it on loopback unless a
private or authenticated transport protects it.

## Capacity checks

Revisit capacity after material changes in Live State or traffic:

```sh
parano1d-cli status
parano1d-cli state
parano1d-cli peers
du -sh ~/.parano1d/data
```

Alert on low disk space, repeated peer loss, sustained synchronization lag and
service restarts. For deployment, continue with
[Run a node on Linux](node.md). For mining-specific CPU planning, see
[Internal mining](internal-mining.md).
