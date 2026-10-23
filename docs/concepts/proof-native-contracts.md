# Proof-native contracts

## From live value to live rights

A live payment output answers a simple question: who may spend this value?
A contract also answers: who may claim it, at which height, under which limit,
and which rights remain after the claim? These conditions become part of the
output's cryptographic identity. **Live State can hold an enforceable right to
value, together with the rules for its next valid transformation.**

This is the architectural step from **live value to live rights**. A refundable
payment, a delegated spending budget or a gradual release is a current object
whose transition is proved. Its validity does not require every future node to
retain and replay the application's complete history.

![From live value to live rights](../assets/architecture/proof-native-contracts.svg)

## The proof carries continuity

A contract's public opening contains its program, spending policy, authorities
and current counters. Poseidon2b commits to that opening. Live State holds the
commitment as the output owner, alongside its amount and creation identifier;
it does not add a growing contract-storage database.

An authorized call consumes that exact output incarnation. The block relation
checks the opening, deadline branch, authorization, integer program, payment,
fee and resulting commitment. A continuing call creates a successor; a closing
call releases the remaining value to the committed recipient. `HistoryStep`
proves this transition together with the block and its recursive ancestry.

The next verifier authenticates the present and its proof. It need not obtain
all previous versions of that contract to establish why the current output is
valid. The same slot system still clears spent records and reuses empty space.

## One core, user-defined applications

Programs share the integer interpreter already proved by the block's matrix.
Creating a contract requires no new circuit, per-application proving key,
deployment allowlist or consensus registration. The six wallet templates are
ordinary programs and policies exposed through the same API as custom terms.

| Live right | Application enabled by the current core |
| --- | --- |
| Collect before expiry; recover afterward | Refundable invoices and prepaid claims |
| Spend only after an unlock height | Savings vaults and delayed access |
| Delegate bounded spending while retaining recovery | Service wallets and controlled operational funds |
| Share one budget across successive calls | Period budgets, including payment fees |
| Claim one prepaid amount when due | Recurring payments initiated by the payee |
| Release anchored tranches with catch-up | Gradual distribution and vesting |

Applications can combine these rights with their own interface, notifications
and authorized transaction submission. They can use the exact same contracts
through GUI, CLI or RPC. Their application logic does not have to become a
permanent execution archive required by every network participant.

## A bounded foundation with room for applications

ABI 3 has two persistent `u64` counters, two scratch registers and sixteen
ordered instructions with checked arithmetic and conditions. There are no
loops, cross-contract calls, external data reads or automatic timers. A due
payment needs an authorized call. All three proof classes support this same core;
the optional Large class adds ordinary payment capacity.

Current public terms and portable receipts remain useful application data.
Wallets retain watched openings and calls locally. A participant who missed
an already-pruned call may need its updated terms or receipt from another
participant. Proof-native validity removes mandatory history replay; it does
not make application data or backups unnecessary.

The opportunity is a reusable foundation for applications built around
verifiable, transferable value and precise spending rights, while the network
continues to authenticate an exact live present. The available instruction and
block budgets are explicit, and application design can work within them today.

Start with the
[contract guide](../contracts/index.md), [lifecycle](../contracts/lifecycle.md)
and [integer core](../contracts/core.md).
