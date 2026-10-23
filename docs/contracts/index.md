# Contracts

A **proof-native contract** holds NOID under a committed program and spending
policy. The same recursive block proof that authenticates payments proves each
contract transition. Users share one bounded core; they do not create a new
proof system for each application.

Read [From live value to live rights](../concepts/proof-native-contracts.md)
for the architectural idea. This section explains how to build and use it.

| Task | Guide |
| --- | --- |
| Understand terms, deposits, calls and successors | [Lifecycle and mechanics](lifecycle.md) |
| Review instructions, counters and authorization | [Integer core and ABI](core.md) |
| Write and verify a native contract program | [Pruv language and walkthrough](pruv.md) |
| Choose a ready-made policy | [Six templates](templates.md) |
| Integrate an application or use the CLI | [API and integration](api.md) |
| Create, share and use contracts in the wallet | [GUI walkthrough](gui.md) |
| Exchange receipts or recover after being offline | [Receipts and recovery](receipts-and-recovery.md) |

## Block capacity

Use `getContractProtocol` to inspect the installed runtime and block limits.
Funding and calls require `runtime_available = true`.

| Class | Pages | Live inputs | Contract calls |
| --- | ---: | ---: | ---: |
| Small, m23 | 63 | 504 | 63 |
| Large, m24 | 206 | 504 | 63 |
| Native, m24 | 63 | 504 | 63 |

Calls and payments share page space. A call uses one page and one live input;
an ordinary payment may use several pages and inputs. Small can hold 63 calls
or 63 one-page payments. Large can hold 63 calls plus 143 one-page payments,
subject to the common 504-input budget. The primary coinbase is separate; an
additional mandatory system page takes one page from these budgets.

## What to keep

The chain authenticates the current commitment and value. Keep your wallet
secret, public contract terms and any receipts you need. A secret alone cannot
recreate an arbitrary program or missed counter updates. The wallet discovers
locally watched successors and merges received evidence without replacing its
own journal. A shared contract file carries terms and at most one matching
receipt, rather than a complete archive of all participants' actions.

Saving unfunded terms is free. Funding and calls have their own network fees.
**Call fee limit** is the policy ceiling for a future call, not a creation fee.

## Native financial contracts

Native proof-verified contracts cover tokens, curves, DEX pools and
NFT listings. The shared recursive block proof enforces ownership, reserves
and atomic transfers. These typed operations run in Native alongside ABI 3
calls and ordinary payments.

Use [Pruv native templates](native-templates.md) to generate reviewed node
requests. The wallet guides cover [tokens](../wallet/tokens.md) and
[NFTs](../wallet/nfts.md). Exact rules are in [Native finance](../protocol/native-finance.md).
