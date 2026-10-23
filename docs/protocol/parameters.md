# Consensus parameters

Mainnet genesis is 2026-08-21 16:00:00 UTC (`1787328000`).

| Parameter | Value |
| --- | --- |
| Target block interval | 30 s |
| ASERT reference epoch / half-life | 6 blocks / 180 s |
| Median-time-past / future drift | 11 headers / 120 s |
| Transaction epoch | 144 blocks ≈ 72 min |
| Hard finality / maximum reorg | 18 / 17 blocks |
| Authenticated recent suffix | 18 blocks ≈ 9 min |
| Body / undo retention | 42 / 36 blocks ≈ 21 / 18 min |
| Small | m23 / 63 pages / 504 inputs / 63 calls |
| Large | m24 / 206 pages / 504 inputs / 63 calls |
| Native | m24 / 63 pages / 504 inputs / 63 calls, native finance |
| Contract ABI | 3 / 16 instructions / 2 persistent u64 / 2 scratch u64 |
| State domain / segment | 2^24…2^32 / 2^16 slots |
| Expansion | ≥75% occupancy in 10 of 18 finalized headers |
| Touched segments per block | 256 |
| Physical page | 323 bytes / 8 inputs / 2 outputs |
| Ordinary logical transaction | 1…128 pages, subject to class page/input budgets |
| Header / canonical block decode cap | 212 / 82,905 bytes |
| Complete native block-body payload cap | 713,689 bytes |
| Transaction tree | 256 leaves, logical transaction IDs |
| Terminal transport cap | 1,100,000 bytes |
| One-time fork-origin response cap | 48 MiB |
| Authorization / ordinary intent wire caps | 256 KiB / 303,495 bytes |
| Ordinary / contract receipt decode caps | 128 KiB / 1,110,624 bytes |
| RPC HTTP request cap | 2,237,632 bytes |
| Mempool count / byte budget | 1,024 / 384 MiB |
| P2P / local RPC | 9600 / 9601 |
| External template lifetime | 30 s after preparation |

Page, input and call budgets apply together. A call uses one page and one
input. Small holds 63 one-page payments or 63 calls; Large holds 206 one-page
payments or 63 calls plus 143 payments, subject to 504 total live inputs.
The primary coinbase is separate. An additional mandatory system page reduces
available user pages to 62 or 205 on that block.

Small and Native are considered automatically.
`--v2-large-blocks` additionally permits Large. The node selects one candidate
by claimable fees and constructs one proof. Every updated node verifies all
three classes. The GUI has no mining workspace.

The physical codec accepts up to 256 bodies, 1,020 inputs and 256 outputs in a
logical spend where applicable to historical data. Admission additionally
requires at most 504 inputs and the selected class's page budget. Never use a
wire-codec bound as a promised active capacity. Counts in blocks are consensus
rules; minute equivalents use the target interval and are not deadlines.

Issuance is 16 → 11.30 → 8 → 5.65 → 4 → 2.83 → 2 → 1.41 → 1 NOID,
one step per 1,051,200 blocks on the height schedule. See [network economics](economics.md)
for exact amounts, fees and rationale; [contracts](../contracts/index.md) for
core limits, and [performance](../reference/performance.md) for measured costs.

Native additionally budgets 48 trade policies, 64 shared funding inputs, 128
typed actions and four markets. These limits apply simultaneously. See
[Native finance](native-finance.md) and [wire formats](native-wire.md).
