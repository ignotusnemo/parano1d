# Native finance

The native profile supports backed fungible tokens, a launchpad, sequential
trading and a fixed-price NFT marketplace inside the State transition proved
by HistoryStep. `getNativeProtocol` reports the installed capacities.

## Identity and ownership

A token's `asset_id` commits to its definition and the exact consumed funding
input at creation: chain, owner, slot and creation ID. A collection uses the
same funding-anchor construction. Its NFTs are identified by collection ID
and serial. Names and tickers describe these identities; two assets may use
the same ticker.

Current typed openings commit to token quantities, reserve balances, market
reserves, NFT ownership and listing terms. Their roots and exact incarnations
are authenticated by State. A native transition consumes its inputs and
creates its outputs atomically. The enclosing relation binds their full body,
Owner authorization, amounts, fees and State actions.

## Fixed supply and holder backing

Fungible tokens are created through the launchpad. Supply is fixed at creation,
with six decimal places and at least 100,000 whole tokens. The creator funds
at least 0.001 NOID per whole token. For example, creating 100,000 tokens
requires 100 NOID of holder backing, plus the quoted network fee.

The reserve and trading liquidity are separate State objects. All outstanding
tokens count towards reserve obligations, including tokens held by the curve
or DEX. Creator authority provides no reserve-withdrawal or additional-mint
operation in this profile.

For reserve `R`, outstanding base units `S` and a burn of `q` units:

```text
payout = floor(R * q / S)
next_reserve = R - payout
next_outstanding = S - q
```

Burn and redemption are one atomic operation. Floor rounding leaves any
fractional remainder in the reserve. Backing per remaining unit cannot
fall. Burning the last outstanding units returns the entire remaining
reserve. The wallet separately quotes the network fee and net NOID outcome.

## Standard launch curve

Let `S0` be the initial supply in token base units and `q` the quantity sold
by the curve. The standard profile fixes:

```text
curve allocation = 3 * S0 / 5
graduation token liquidity = 2 * S0 / 5
curve NOID cash C(q) = ceil((3 * S0 * q + 5 * q * q) / (900 * S0))
graduation NOID cash = S0 / 250
marginal price = (3 * S0 + 10 * q) / (900 * S0)
```

Cash is in microNOID. Both NOID and the token have six decimal places, so the
marginal-price ratio is also NOID per whole token. It starts at `1/300` and
reaches `1/100` at graduation. Execution uses exact integer cash differences;
the marginal price is a display reference.

Creation may include an initial creator purchase of `q` base units, with
`0 <= q <= 3 * S0 / 5`. The same atomic transition deposits the full holder
backing, pays `C(q)` into trading custody and assigns `q` tokens to the creator.
The curve starts with inventory `S0 - q` and cash `C(q)`. A purchase of the full
curve allocation instead creates the permanent DEX pool immediately, with
`2 * S0 / 5` token units, `S0 / 250` microNOID and `S0 / 25` permanently locked
pool shares. Creator purchase, custody and backing are checked together by
the native creation relation. Asset identity and fixed supply use the same
creation funding anchor for every initial purchase quantity.

| Whole-token supply | Holder backing | Curve allocation | DEX allocation | NOID liquidity at graduation |
|---:|---:|---:|---:|---:|
| 100,000 | 100 | 60,000 | 40,000 | 400 |
| 1,000,000 | 1,000 | 600,000 | 400,000 | 4,000 |
| 5,000,000 | 5,000 | 3,000,000 | 2,000,000 | 20,000 |

A buy obtains the largest affordable integer quantity. A sell receives the
corresponding decrease in `C(q)`. Reaching the curve allocation automatically
creates the permanent NOID/token pool in the same transition. Asset identity
and holder balances remain unchanged. A crossing buy can spend its remainder
against the newly created pool; an unusable dust remainder is returned.

## Permanent DEX liquidity

The initial pool price equals the final curve marginal price. Pool liquidity
is permanently locked. There is no user LP issuance or withdrawal workflow
in this profile. DEX fees accrue inside its reserves.

For input reserve `x`, output reserve `y` and gross input `g`:

```text
fee = ceil(30 * g / 10000)
effective_input = g - fee
output = floor(y * effective_input / (x + effective_input))
next_input_reserve = x + g
next_output_reserve = y - output
```

The fee is 0.3% of input, rounded up to a base unit. Curve-only execution uses
its cash function; the DEX fee applies to a DEX execution or the DEX portion
of a crossing buy. Network fees are quoted separately. Every accepted swap
preserves positive reserves and a nondecreasing reserve product.

## Multiple trades in one block

Each Owner-authorized policy fixes chain, epoch, asset, owner, recipient,
gross input, minimum output, maximum network fee and inclusion-height range.
Exact funding inputs are committed to its authorization ID.

For a selected set, the relation derives each priority from the immutable
parent and the policy's principal funding input. It orders those priorities
and chooses the next side according to the current price relative to the
block's initial price. Buys are preferred at or below that price; sells above
it. Every executed trade uses the preceding trade's resulting reserves or
curve position. This supports several buys and sells in one block.

The complete selected sequence, intermediate prices, funding and final payouts
are checked by the native relation and recursion. Increasing a fee or
rewriting an output recipient cannot directly buy a different position.
Miners control inclusion; available funding identities and the selected set
can affect execution. Every fill must still meet the owner's minimum,
recipient, amount, fee and expiry bounds. An unfilled policy does not spend
its funding.

Pending estimates use the local node's known candidate set. Different nodes
can see different pending sets. The confirmed block fixes the final sequence
and each participant's exact outcome.

## NFT marketplace

Wallet collections use the full u64 serial range. The creator can add items
in later minting transactions. Minting consumes and updates the collection's
issuance counter. A burned serial stays issued. The wallet's simple Create NFT
flow prepares a one-item collection and then mints its item, with each stage
reviewed separately.

Listing consumes an owned NFT and creates exact seller, item, ask and expiry
terms. Its fee credit is 0.1 NOID. A purchase consumes that exact listing,
pays the seller and returns the item to the buyer in one transition. The
seller receives the ask and listing credit. Cancellation returns the NFT and
remaining credit after its network fee. Concurrent purchases conflict on the
same listing incarnation, so one NFT cannot be delivered to two buyers.

## Proof and storage budgets

The authenticated bank selects one class per block:

| Class | Physical pages | Ordinary live-input capacity | ABI 3 call slots |
|---|---:|---:|---:|
| Small | 63 | 504 | 63 |
| Large | 206 | 504 | 63 |
| Native | 63 | 504 | 63 |

Small and Large cover NOID payments and ABI 3 calls. Native adds token,
launchpad, DEX and NFT operations. A Native block can also include NOID
payments and ABI 3 calls within its shared page and input budgets.

Template selection considers Small and Native automatically automatically.
`--v2-large-blocks` additionally permits Large. The node selects the candidate
with the greatest claimable fees and builds one proof for that candidate.
Ties retain the earlier candidate, with Small considered first. External
miners receive the existing PoW template and submit the nonce through the
same mining API.

The Native class additionally budgets up to 48 trade policies, 64 shared
funding inputs, 128 typed actions and four markets. These are simultaneous
resource bounds; actual policy capacity depends on funding and payout shape.
For example, 32 policies with two funding inputs each use the entire
64-input budget. The node's template selection accounts for ordinary payments
and ABI 3 calls in the same block.

Recent bodies carry native transaction data. Current live openings and their
required definitions accompany authenticated State synchronization. Bodies
expire after retention; live rights remain in State and exported receipts
remain checkable against canonical headers.

See [Native objects and wire formats](native-wire.md) for kinds, canonical
framing, provenance and live-payload synchronization.
