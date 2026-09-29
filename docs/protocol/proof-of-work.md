# Proof of work

Parano1d proof of work is a domain-separated Poseidon2b digest over the fixed
semantic header fields. It runs after the nonce-independent `HistoryStep` has
been proved.

## Field schedule

The `POWHDR__` sponge absorbs exactly 16 `GF(2^128)` elements:

| Index | Field |
|---:|---|
| 0–1 | `prev_block_hash` |
| 2–3 | `state_root` |
| 4–5 | `tx_root` |
| 6 | `timestamp` |
| 7 | `height` |
| 8–9 | `miner_address` |
| 10 | 128-bit nonce |
| 11–12 | `difficulty_target` |
| 13 | `log_slots` |
| 14 | `active_slot_count` |
| 15 | `alloc_counter` |

Thirty-two-byte values are split into two little-endian 128-bit halves. Scalar
integers are zero-extended. With sponge rate two, the schedule is exactly eight
rate blocks and needs no variable-length padding.

The PoW domain differs from both nonce-bearing block identity and the
nonce-free semantic header commitment.

## Target comparison

The digest and target are interpreted as 256-bit little-endian integers. A
nonce is valid only when:

```text
pow_digest < difficulty_target
```

Equality fails.

## ASERT

The target interval between accepted blocks is 30 seconds. Proof preparation,
nonce search and propagation all occupy that interval. ASERT uses a six-block
reference epoch and a 180-second half-life. From v2 activation at height 210,537,
validation derives each block's exact target from the canonical anchor and its
parent's height and timestamp. Siblings of the same parent have the same target;
changing a candidate's timestamp cannot change its work.

A timestamp must also be greater than median time past over the previous 11
headers and no more than 120 seconds ahead of the validating node's wall clock.

## Runtime kernels

The same fixed permutation is evaluated in packed nonce batches. The production
binary selects the best supported implementation at runtime:

- `pclmul` baseline on x86-64;
- `avx2+vpclmul` where available;
- `avx512bw+vpclmul` on supported hosts;
- `neon+pmull` on ARM64.

Packed execution changes throughput, not the digest. The scalar implementation
is a test oracle and is not a production fallback.

## External mining boundary

An external worker receives the exact 16-field schedule, nonce index and target.
It returns only a canonical 16-byte little-endian nonce. The node checks it
against the immutable, single-use template before committing a block.

The worker cannot alter a transaction, State root, payout or proof. A solved
nonce for an expired or stale template is rejected.
