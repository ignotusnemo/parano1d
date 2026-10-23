# Protocol parameter reference

The complete [consensus table](../protocol/parameters.md) is the authoritative
parameter guide. Mainnet uses 30-second blocks; Small m23 is 63 pages / 504 inputs /
63 calls, opt-in Large m24 is 206 / 504 / 63 and automatic Native m24 is
63 / 504 / 63 with native finance. These limits apply together.

| Topic | Reference |
| --- | --- |
| Timing, windows, State, wire limits | [Consensus parameters](../protocol/parameters.md) |
| Issuance and fees | [Network economics](../protocol/economics.md) |
| ABI, program and counters | [Contract core](../contracts/core.md) |
| Proof assumptions and exact accounting | [Security model](../protocol/security-model.md) |
| Actual proving and verification costs | [Performance](performance.md) |

`paranoid_getContractProtocol` returns installed contract limits and runtime
status. The trace field is GF(2^128), the wide challenge field GF(2^256),
with a trace-one challenge support of size 2^255. The C1 profile uses 65 wallet
queries and 133 History queries. Poseidon2b has width 4, S-box x^7, 8 full and
58 partial rounds. These algorithm parameters are not throughput guarantees.
