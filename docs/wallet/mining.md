# Mining with Core

Run mining through the Core daemon or an external worker. The wallet
provides Main, Tokens, NFT, Receipts, Scope, Contracts and Settings.

## Internal Core miner

Check the host, then choose the CPU budget for its built-in miner:

```sh
parano1d --check-hardware
parano1d --mode miner --cpu-threads 6
```

Core constructs the recursive block proof and searches for a valid nonce.
Use a dedicated miner data directory when running Core alongside the wallet.
The active or explicitly configured payout address receives new block rewards.

## External workers and pools

The backend node constructs the proof and publishes an immutable PoW template.
External workers search its nonce space and submit a solution. This keeps
block proving on the backend while workers perform the same PoW algorithm.

See [internal mining](../operate/internal-mining.md) for Core deployment,
[external mining](../operate/external-miner.md) for workers and pools, and
[mining profiles](../mining/index.md) for the active proof budgets.

The wallet follows rewards through its verified node. Main shows spendable
NOID outputs and Scope opens retained blocks and permanent headers.
