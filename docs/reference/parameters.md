# Protocol parameter reference

## Core

```text
block target             20 seconds
ASERT epoch               6 blocks
ASERT half-life         120 seconds
median-time-past         11 headers
future drift            120 seconds
transaction epoch       144 blocks
hard finality            18 blocks
```

## State

```text
initial domain           2^24 slots
maximum domain           2^32 slots
segment                  2^16 slots
expansion threshold      75%
finalized sample         18 headers
expansion majority       10 / 18
```

## Transactions and blocks

```text
Tx8x2 page               8 inputs / 2 outputs / 323 bytes
PagedSpend               1..128 pages
logical input cap        1,020
logical output cap       256
block body cap           256 fixed bodies
ordinary user pages      255
payout-block user pages  254
block user outputs       510
touched segments         256
```

## Proof system

```text
committed trace field    GF(2^128)
wide challenge field     GF(2^256)
challenge support        2^255
Poseidon2b width         4
S-box                    x^7
full rounds              8
partial rounds           58
B25                      m=22, up to 25 positions
B255                     m=24, up to 255 positions
wallet queries           65
History/BaseFold queries 133
B25 codeword             2^19 at rate 1/4
B255 codeword            2^21 at rate 1/4
serialized authorization max 92,696 bytes
target FRI security      128 bits
Block–Tiwari provable    127 bits
Block–Tiwari conjectured 127 bits
ideal-QROM boundary      64.707407428576 bits
NIST Post-Quantum Cryptography Category 1
Category 1 gate-depth floor 173.391078499301 bits
```

## Monetary

```text
1 NOID                   1,000,000 μNOID
initial subsidy          50 NOID
subsidy floor            1 NOID
base fee                 5,000 μNOID
input fee                100 μNOID
output fee               700 μNOID
base growth fee          2,500 μNOID / net-new slot
```

The explanatory and boundary rules are in
[Consensus parameters](../protocol/parameters.md).
