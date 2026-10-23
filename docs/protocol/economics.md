# Network economics

**Block height determines issuance. Live State occupancy prices persistent
storage.** NOID pays network fees, backs issued tokens and supplies the quote
asset for the launchpad and native DEX.

## Unit

```text
1 NOID = 1,000,000 μNOID
```

NOID is the ticker and the wallet uses ①. Consensus uses exact integer
microNOID. A permanent 1 NOID block subsidy supports the tail issuance.

## Issuance

Let `H = 210537` and `I = 1051200`. For height `h >= H`, the tier is
`min((h - H) / I, 8)` with integer division.

| Tier | First height | NOID per block | Gross NOID per full interval |
| ---: | ---: | ---: | ---: |
| 0 | 210,537 | 16 | 16,819,200 |
| 1 | 1,261,737 | 11.30 | 11,878,560 |
| 2 | 2,312,937 | 8 | 8,409,600 |
| 3 | 3,364,137 | 5.65 | 5,939,280 |
| 4 | 4,415,337 | 4 | 4,204,800 |
| 5 | 5,466,537 | 2.83 | 2,974,896 |
| 6 | 6,517,737 | 2 | 2,102,400 |
| 7 | 7,568,937 | 1.41 | 1,482,192 |
| 8 | 8,620,137 | 1 | 1,051,200 |

The last row repeats indefinitely. Each amount is an exact consensus constant.
The block relation proves the reward selected by authenticated height.
State expansion preserves the height schedule.

At the 30-second target, an interval is 365 nominal days. Actual dates follow
block production. The eight declining intervals total 53,810,928 NOID of
scheduled gross subsidy. The first two total 28,697,760 NOID. The tail schedules
1,051,200 NOID per nominal year. Actual live supply follows issued subsidy,
claimed amounts and fee burns.

The curve has anchors `16 → 8 → 4 → 2 → 1` over eight nominal years. Annual
steps use the fixed intermediate amounts 11.30, 5.65, 2.83 and 1.41 NOID.
The permanent tail keeps a block subsidy alongside transaction fees.

## State efficiency

Occupancy raises the price of net-new live slots. That growth component is
burned. Consolidation frees slots and avoids a growth charge. Input and output
fees pay for their actual transaction footprint. Contracts, tokens and NFTs
share these live-State accounting rules.

<a id="existing-allocation-schedule"></a>

## Development allocation

Through block **3,223,778**, the subsidy allocation is:

- 90% to miners.
- 5% to the O(1) Network Fund.
- 5% to Parano1d Lab.

Later block subsidies go entirely to miners. Transaction fees remaining after
the State-growth burn are miner-claimable.

Fund payouts use 2,880-block intervals with the first payout at height 213,416.
The final partial interval is paid at height 3,223,778. Consensus derives the
mandatory system payout from its interval and reward tier. At the 16 NOID tier,
the miner subsidy is 14.4 NOID and each fund receives 2,304 NOID for a complete
interval. These fund shares belong to the gross subsidy allocation.

## Native market fees and backing

Token creation deposits at least 0.001 NOID of holder backing per whole token.
This reserve pays proportional redemption when holders burn tokens. Trading
liquidity is a separate State object.

DEX trades charge 0.3% of input, rounded up to a base unit. This fee stays
inside the pool reserves. Network fees are quoted separately. See
[Native finance](native-finance.md) for the curve, graduation and exact formulas.

## Fees

The minimum transaction fee consists of:

- 5,000 μNOID per logical transaction;
- 100 μNOID per live input;
- 700 μNOID per live output;
- 2,500 μNOID times occupancy pressure for each net-new live slot.

Pressure multipliers are:

| Parent-State occupancy | Multiplier |
|---:|---:|
| Below 50% | 1× |
| 50% to below 75% | 2× |
| 75% to below 90% | 4× |
| 90% and above | 8× |

The State-growth component is burned. Base, input, output and voluntary tip
components are claimable by the miner.

A consolidation that turns several inputs into one output shrinks State and
pays no growth burn.

## Dynamic relay floor

Consensus fees and local relay policy are separate. The local dynamic floor
uses the greater of 5,000 μNOID and 90% of the median fee among the last 50
transactions admitted to that node's mempool, not a network-wide fee estimate.

A raised floor applies only under pressure.
Reaching 80% of either the transaction-count limit or retained-byte limit
enables it. Falling strictly below 50% of both limits, or emptying the mempool,
resets it to the default. Between those thresholds the current pressure state
is retained. The existing limits remain 1,024 transactions and 384 MiB.

A local relay-floor increase does not by itself evict already admitted
transactions. A higher consensus fee caused by parent-State occupancy is
different: normal block cleanup removes transactions that no longer meet that
minimum and releases their local reservations.

Wallet Auto fees use the actual transaction shape, current parent-State
occupancy and the local relay floor. A local fee rejection before admission
can trigger an Auto replan within the existing three-attempt submission
budget. Manual fees and already confirmed consolidation quotes are not
silently increased. There is no extra peer-fee polling, and Auto does not
promise confirmation under every other node's policy.
