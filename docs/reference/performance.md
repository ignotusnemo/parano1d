# Proof performance and capacity

The block proof authenticates the complete State transition and recursive
ancestry. For a fixed profile, terminal verification work and proof size stay
bounded as the chain grows. CPU instructions, memory bandwidth and block
composition determine proof construction time.

## Proof classes

| Class | Outer exponent | Pages | Ordinary live inputs | ABI 3 calls | Workload |
| --- | ---: | ---: | ---: | ---: | --- |
| Small | 23 | 63 | 504 | 63 | NOID payments and ABI 3 calls |
| Large | 24 | 206 | 504 | 63 | NOID payments and ABI 3 calls |
| Native | 24 | 63 | 504 | 63 | Payments, ABI 3, tokens, launchpad, DEX and NFTs |

The authenticated bank is
`6c280ae869afc25e31d46d73b42870512991b78c9498bc7e5ef939bc07e5ed5e`.
Its matrices contain 7,105,515 Small rows, 16,733,463 Large rows and 13,618,333
Native rows. The serialized terminal cap is **1,100,000 bytes**.

Native additionally budgets 48 trade policies, 64 shared funding inputs,
128 typed actions and four markets. These limits apply together with pages,
inputs and State actions. The enclosing proof covers native execution and
validity back to genesis.

## One selected proof

The producer considers Small and Native automatically. `--v2-large-blocks`
additionally permits Large. It chooses one candidate by claimable fees and
constructs one proof. All nodes verify all three classes.

An almost empty block still proves the selected fixed relation. Transaction
count, page occupancy and proving time therefore describe different resources.
The complete block interval includes selection, assembly, recursive proving,
nonce search, transport and acceptance. ASERT targets their combined
30-second cadence.

## Hardware and measurement

Production x86-64 requires SSE4.1 and PCLMULQDQ. Runtime dispatch can select
PCLMUL, AVX2+VPCLMUL or AVX-512+VPCLMUL. ARM64 requires NEON and PMULL.

Size producer servers for their block workload. Size seed and receiving nodes
for proof verification, State application and network traffic. Measure proof
construction, verification and application separately. Record the hardware,
backend, worker count, CPU allocation, memory limit, cache state and workload
with each timing. Include preparation when reporting complete block proving.

See [hardware](../operate/hardware.md), [class selection](../architecture/mining.md)
and [native finance](../protocol/native-finance.md) for deployment and resource rules.
