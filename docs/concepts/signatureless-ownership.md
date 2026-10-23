# Signatureless ownership

An ordinary Parano1d owner address is the Poseidon2b image of a 256-bit secret. Spending does
not reveal a public key and does not attach a digital signature. The wallet
instead produces a zero-knowledge proof that it knows the preimage behind the
input owner.

Authorization is bound to:

```text
{logical transaction ID, input owner}
```

Changing the recipient, amount, fee, input set, output set or page order
changes the logical transaction ID and invalidates the authorization.

## One secret, deterministic addresses

The wallet stores one 256-bit master secret and derives indexed owner secrets
from it. Address index `0` is created first; further addresses are generated
without maintaining independent private-key files.

The active address is a wallet choice, not a consensus property. It determines
which owner the wallet uses for spending and internal mining payout. Funds
belonging to other derived addresses remain visible but are not silently mixed
into the active address's transaction.

## Fresh proof on every spend

Authorization capsules are freshly randomized and witness-hiding. Reusing an
address does not result in a repeated signature or a stable proof transcript.
The secret stays inside the wallet prover and is consumed through a
zeroizing boundary.

The authorization does not contain a UTXO Merkle path. It proves ownership,
not current spendability. This makes it independent of a particular State
root and allows the public State witness to advance while the transaction is
being constructed.

The miner separately proves that the referenced inputs are live and that the
complete State transition is valid.

## What is public

Signatureless does not mean private.

Addresses, amounts, fees, input references, output records and relayed
transactions are public. Zero knowledge hides the spending secret. It does not
hide transaction history while that history is available.

Parano1d reduces permanent historical exposure by making old block bodies
unnecessary for consensus. A saved receipt can still prove a specific payment
after its body has been pruned.

## Post-quantum boundary

Transaction ownership contains no elliptic-curve signature scheme. Address
derivation and committed authorization traces use Poseidon2b and `GF(2^128)`.
The production C1 profile samples authorization challenges from a
`2^255`-element trace-one support in `GF(2^256)`.

The Ed25519 identity used by libp2p is outside this boundary. It identifies a
network peer; it cannot authorize a transaction, create value or satisfy any
consensus ownership rule.

The [security model](../protocol/security-model.md) gives the ancestry resource
assessment, including historical ancestry and matrix retirement.

## Operational consequence

The master secret is the wallet. Anyone who learns it can derive the same
addresses and authorize their funds. There is no separate public/private-key
backup and no recovery service.

A photo-derived secret has the same on-chain form as a generated or imported
secret. The original pixels must remain byte-for-byte reproducible: editing,
resizing or messenger recompression derives a different secret.

See [First run](../wallet/first-run.md) and
[Backup and recovery](../wallet/backup-recovery.md) before funding a wallet.

## Contract authority

A contract State owner is a commitment to public terms and counters. The call
proves knowledge of the active claim or recovery authority's secret; the block
proof additionally enforces program and policy. Knowing that secret does not
permit bypassing the committed restrictions. See [live rights](proof-native-contracts.md).
