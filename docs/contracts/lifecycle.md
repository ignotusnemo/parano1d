# Lifecycle and mechanics

## 1. Define public terms

An opening describes a program, two persistent counters, two authorization
branches, two closing recipients, a deadline and spending limits. Its address
is a Poseidon2b commitment to those terms and counters. Anyone can prepare,
inspect or share terms without publishing a transaction.

The program and policy do not change during a continuing call. Only the two
counters can change. A new counter state can therefore have a new address even
though it belongs to the same immutable contract rules. Wallets group these
states for convenience; the consensus identity remains the exact commitment.

## 2. Fund an instance

Funding is an ordinary authorized payment to the opening's address. It creates
a live output containing the amount, commitment and a fresh `creation_id`.
The term file itself is not evidence that funding occurred. Query verified
State for the current output or verify a funding receipt and then query State.

Every deposit is independent. Two payments to the same opening create two
instances with their own values and counters. They do not replenish one shared
budget or merge automatically. One call consumes one instance. Ordinary wallet
balance queries do not treat outputs owned by a contract commitment as directly
spendable outputs of your normal address; use the contract's balance view.

In the official wallet, funding is enabled only when the next candidate block
uses the contract relation. It has a separate fee preview. Saving terms without funding is free.

## 3. Review the next call

Identify the opening and the exact `(slot_index, creation_id)` of a funded
instance. A reused slot index alone is never sufficient. At candidate height
`h`, the committed deadline selects the branch:

| Condition | Authority and closing recipient |
| --- | --- |
| `h < deadline_height` | Claim branch |
| `h >= deadline_height` | Recovery branch |

Each branch separately permits continuing and/or closing. The authority proves
knowledge of its ordinary spending secret with a fresh wallet capsule bound
to the complete logical transaction. The contract commitment is the input
owner; the selected authority is the party that authorizes its use.

`previewObjectCall` constructs the proposed body, inclusion height, actual fee,
payment and successor. Use all returned review guards for submission. A tip
change can alter the height, active branch, available input or allocated output
positions. Refresh and review a changed transaction rather than silently
authorizing a different one.

## 4. Continue or close

| Call | Input | Output 0 | Optional output 1 |
| --- | --- | --- | --- |
| Continue without payment | One exact contract output | Successor contract | None |
| Continue with payment | One exact contract output | Successor contract | Permitted recipient and amount |
| Close | One exact contract output | Remaining value to the branch's closing recipient | None |

Every call occupies one physical page. Its fee is paid from the consumed
contract value. A continuing call obeys `max_fee`, `max_payout` and
`min_retained`; the payout cap excludes the fee. A closing call still obeys
`max_fee` and the program, but the continuing payout and reserve caps do not
limit withdrawal of the remaining value. Programs can impose additional
conditions on either form.

The `unrestricted_payout_recipient` mode applies only to continuing payments.
It does not change the committed recipient of a closing call. Every live output
must have a positive amount. A zero-value contract cannot remain as a free
standalone storage record.

Value is conserved: input equals retained value plus payment plus fee. On close,
retained value is zero and the closing recipient receives input minus fee.
The existing State-growth fee and burn rules apply to the actual output shape.

## 5. Prove and confirm

The mempool performs admission checks and reserves conflicting resources.
In the block, contract calls form a canonical prefix before ordinary user
payments. The relation binds each opening to its consumed commitment, proves
the selected authorization and integer execution, and proves the exact State
transition. The block's recursive terminal carries its validity forward.

Submission is not confirmation. A pending successor is a candidate until its
transaction is accepted. A conflicting call can spend the same instance first;
a shallow reorganization can replace a confirmed call. The wallet rechecks
canonical headers and current State instead of trusting saved GUI status.
Finality remains 18 blocks, with at most 17 blocks of accepted rollback.

## 6. Keep the live right and useful evidence

After a continuing call, retain its successor opening. After any call, a
portable receipt can preserve the original terms, operation and proof. It
remains verifiable after ordinary block-body pruning. It does not prove that
the successor is still unspent.

An observer with known terms can check current balances from State. If it missed
an already-pruned call that changed the counters, it needs the new opening or
a receipt to identify the successor. See [receipts and recovery](receipts-and-recovery.md)
for the exact local-journal and import behavior.
