# GoldXCoin (GXC): A Hybrid-Consensus Blockchain with Enforced Provenance

**Technical Whitepaper — Protocol Version 70015**

*This document describes the protocol as implemented in this repository. Every
formula, constant, and rule below is taken from the source and is exercised by
the test suite; each section cites the file it derives from and the tests that
pin it down. Where something is designed but not yet built, it is marked
**Not implemented**. Nothing here is aspirational.*

---

## Contents

1. [Abstract](#1-abstract)
2. [Design goals and non-goals](#2-design-goals-and-non-goals)
3. [Cryptographic primitives](#3-cryptographic-primitives)
4. [The 256-bit target model](#4-the-256-bit-target-model)
5. [Consensus](#5-consensus)
6. [Transactions](#6-transactions)
7. [Proof of Traceability](#7-proof-of-traceability)
8. [The Proof-of-Work Receipt](#8-the-proof-of-work-receipt)
9. [Monetary policy](#9-monetary-policy)
10. [Staking and validator selection](#10-staking-and-validator-selection)
11. [Taint propagation and fraud detection](#11-taint-propagation-and-fraud-detection)
12. [The reversal pipeline](#12-the-reversal-pipeline)
13. [Network protocol](#13-network-protocol)
14. [Storage](#14-storage)
15. [Subsystems built on the core](#15-subsystems-built-on-the-core)
16. [Security analysis](#16-security-analysis)
17. [Known limitations](#17-known-limitations)
18. [Parameter reference](#18-parameter-reference)
19. [Verifying the claims in this document](#19-verifying-the-claims-in-this-document)

---

## 1. Abstract

GoldXCoin is a UTXO blockchain that makes the *provenance* of value a
first-class, consensus-enforced property rather than something reconstructed
after the fact by an external analyst.

Two mechanisms carry that weight:

**Proof of Traceability (POT).** Every non-coinbase transaction must name the
transaction it descends from and the amount it inherited, and both must agree
with its first input. Nodes reject transactions where they do not. Following
that declaration backwards from any output walks an unbroken chain of custody
to the coinbase that minted the coins.

**The Proof-of-Work Receipt.** Every mined block carries a digest committing to
the block it extends, its transaction set, the winning nonce, the miner, the
difficulty, and the time. The block's coinbase must carry the same receipt and
the block's own height. A newly minted coin therefore cannot be separated from
the specific proof-of-work that justified minting it.

Around this core the implementation adds hybrid PoW/PoS consensus, multi-algorithm
mining, on-chain taint propagation with an administrative reversal pipeline,
stake-weighted governance, a gold-backed token, tokenized equity contracts, and a
multi-signature cross-chain bridge.

**Maturity.** This is pre-launch software. No mainnet is running, there has been
no external audit, and the consensus rules should be treated as a specification
under review rather than a settled protocol. Section 17 is explicit about what is
weak. Read it before deploying anything.

---

## 2. Design goals and non-goals

**Goals.**

- *Provenance is checked, not inferred.* Chain-of-custody validity is a rule of
  the protocol, applied at the point a transaction enters a block.
- *Issuance is accountable.* Every unit of new supply is bound to a verifiable
  proof-of-work solution at a specific height.
- *One definition of validity.* The miner and the validator must derive "meets
  the target" from the same function. Divergence there is not a bug that
  degrades the chain, it is one that stops it.
- *Recovery from theft without unilateral seizure.* A reversal requires taint
  evidence, a generated proof, and multi-party administrative approval.

**Non-goals.**

- GXC does not offer anonymity. POT is designed to make flows *more* traceable,
  not less. If untraceability is your requirement, this is the wrong chain.
- GXC is not a smart-contract platform. There is no general VM; contracts are
  specific typed constructs (gold token, stock contracts) implemented natively.
- The reversal pipeline is deliberately not trustless. It is an administrative
  process with cryptographic evidence, and Section 12 says plainly who is
  trusted.

---

## 3. Cryptographic primitives

| Purpose | Algorithm | Source |
|---|---|---|
| Signatures | ECDSA over secp256k1, DER-encoded | `src/Crypto.cpp` |
| Block header hash (SHA-256 chain) | SHA-256d | `src/HashUtils.cpp` |
| Transaction id | Keccak-256 | `src/Keccak256.cpp` |
| Signature hash | SHA-256d | `src/Transaction.cpp` |
| Merkle tree | SHA-256d | `src/HashUtils.cpp` |
| Address derivation | RIPEMD-160(SHA-256(pubkey)) | `src/Crypto.cpp` |
| ASIC-resistant PoW | Argon2id (64 MiB, t=3, p=4) | `src/Argon2id.cpp` |
| Salt derivation for GXHash | BLAKE2b | `src/Blake2b.cpp` |

**SHA-256d** is the Bitcoin construction: the second round runs over the 32 raw
bytes of the first digest, not over its hexadecimal rendering.

```
SHA256d(m) = SHA256(SHA256(m))
```

**Keccak-256** is original Keccak (0x01 domain padding), not SHA3-256 (0x06).
The two produce entirely different digests from the same input; GXC uses the
former, matching Ethereum's convention. The implementation is in-tree because
OpenSSL 3.x does not expose a `KECCAK-256` digest.

```
Keccak-256("")    = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
Keccak-256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
```

**Addresses** are `prefix || first 34 hex chars of RIPEMD-160(SHA-256(pubkey))`,
with prefix `GXC` on mainnet and `tGXC` on testnet.

> **Not implemented:** addresses carry no checksum. A mistyped address is
> indistinguishable from a valid one, and funds sent to it are unrecoverable.
> See Section 17.

*Tests: `tests/test_crypto.cpp` — known-answer vectors for every digest,
sign/verify round-trips, tamper rejection, address determinism.*

---

## 4. The 256-bit target model

Difficulty in GXC denotes a **target**: a 256-bit upper bound that a block hash,
read as a big-endian integer, must not exceed.

```
target(D) = powLimit / D

valid(H, D)  ⟺  int256(H) ≤ target(D)
```

`powLimit` is the largest permitted target and is network-specific:

| Network | Compact | powLimit |
|---|---|---|
| Mainnet | `0x1d00ffff` | `00000000ffff0000…0000` (224 bits) |
| Testnet | `0x207fffff` | `7fffff0000…0000` (255 bits) |

Mainnet reuses Bitcoin's difficulty-1 target, so a difficulty of *D* denotes the
same expected work it denotes on Bitcoin: roughly `D × 2³²` hashes. Testnet uses
a near-maximal target so a single CPU finds blocks immediately, which is what
makes the network usable for development.

Work contributed by a block, used for fork choice, is the expected number of
hashes needed to find it:

```
work(target) = 2²⁵⁶ / (target + 1)
```

evaluated inside 256 bits via the identity `2²⁵⁶/(t+1) ≡ ~t/(t+1) + 1`.

Chainwork is the running sum of `work` over the chain, and the chain with the
greatest accumulated chainwork wins. Comparing heights rather than work would let
an attacker win with many low-difficulty blocks.

**One predicate, two callers.** `meetsTarget()` in `src/HashUtils.cpp` is the
only definition of proof-of-work validity. `Block::mineBlock()` searches against
it and `Blockchain::validateProofOfWork()` verifies against it. This is a
structural requirement, not a stylistic one: an earlier revision of this codebase
had the miner counting leading zero *bytes* while the validator counted leading
hex *zeros* against the raw difficulty value, which at the mainnet floor of 1000
demanded 1000 leading zeros in a 64-character string. No block could satisfy it,
and the mainnet chain could not have advanced past genesis.

*Source: `src/arith_uint256.cpp`, `src/HashUtils.cpp`.
Tests: `tests/test_arith_uint256.cpp` (compact encoding, division, target
round-trips), `tests/test_block.cpp` (`ProofOfWork.*` — boundary inclusivity,
miner/validator agreement, mainnet floor satisfiability).*

---

## 5. Consensus

### 5.1 Block types

```cpp
enum class BlockType { POW_SHA256, POW_ETHASH, POW_GXHASH, POS };
```

Three proof-of-work algorithms and one proof-of-stake type share a chain. The
header hash is computed with the algorithm the block declares:

```
H(B) = SHA256d(index ‖ prevHash ‖ timestamp ‖ merkleRoot ‖ nonce)   [POW_SHA256]
     = Ethash (index ‖ … ‖ nonce)                                    [POW_ETHASH]
     = GXHash (index ‖ … ‖ nonce)                                    [POW_GXHASH]
     = SHA256 (index ‖ … ‖ nonce)                                    [POS]
```

### 5.2 Block validation

A block is accepted only if all of the following hold
(`Blockchain::validateBlockInternal`):

1. **Height** is exactly one past the current tip.
2. **Linkage:** `prevHash` equals the tip's hash.
3. **Merkle root** recomputed from the block's transactions equals the declared
   root.
4. **Header hash** recomputed from the block's contents equals the declared hash.
5. **Target:** `meetsTarget(hash, difficulty, network)` (PoW), or the validator
   signature verifies over the PoS commitment (PoS).
6. **Difficulty** matches what the network requires at this height, subject to a
   per-network floor.
7. **Work receipt** verifies (Section 8).
8. **Coinbase:** exactly one, at index 0, paying no more than
   `reward(height) + fees`.
9. **Every transaction** independently validates, including POT.
10. **No double-spend:** every input references a UTXO in the current set at the
    claimed amount.

Steps 3 and 4 deserve emphasis. Without them the proof-of-work is free: a miner
can present any 64-character string with sufficient leading zeros as the block's
hash, never having done the work, because nothing forces the declared hash to be
the one the contents actually produce.

### 5.3 Difficulty adjustment

Every 2016 blocks:

```
D_new = D_old × (T_expected / T_actual)

T_expected = 2016 × targetBlockTime
```

clamped to `[D_old/4, D_old×4]` per retarget, and then to the network's absolute
bounds (mainnet `[1000, 10⁷]`, testnet `[1, 10⁴]`).

### 5.4 Mining

`Block::mineBlock(difficulty, maxAttempts)` fixes the merkle root, then searches
nonces until the header hash meets the target or the attempt budget is exhausted.
It returns whether it succeeded; on success it computes the work receipt and
stamps it onto the coinbase. The budget matters — an unbounded loop cannot be
interrupted to take a new tip, and a miner that cannot abandon stale work is a
miner that wastes it.

*Source: `src/Blockchain.cpp`, `src/block.cpp`.
Tests: `tests/test_block.cpp`.*

---

## 6. Transactions

### 6.1 Structure

```cpp
struct TransactionInput  { txHash; outputIndex; signature; amount; publicKey; };
struct TransactionOutput { address; amount; script; };

enum class TransactionType { NORMAL, STAKE, UNSTAKE, REWARD, COINBASE, REVERSAL };
```

Beyond inputs and outputs, a transaction carries the POT fields (`prevTxHash`,
`referencedAmount`), a fee, an optional memo, a lock time, and — for coinbases —
a work receipt and a block height.

The UTXO set is keyed `txHash || "_" || outputIndex`.

### 6.2 The signature hash

Input signatures commit to a digest over the whole transaction:

```
sighash = SHA256d(
    inputs   : (txHash, outputIndex, amount, publicKey) for each
    outputs  : (address, amount, script) for each
    metadata : prevTxHash, referencedAmount, senderAddress, receiverAddress,
               nonce, fee, memo, lockTime, type, timestamp, popReference
)
```

The signature fields themselves are excluded — a signature cannot commit to its
own value, and a verifier must be able to reconstruct exactly the message the
signer signed.

**Why the outputs must be in there.** A signature that covers only the outpoint
being spent authorizes *spending that coin* without saying anything about where
it goes. Anyone who observes such a transaction — a peer, a relaying node, a
mempool watcher — can substitute their own outputs, keep the original signature,
and the result verifies. The transaction is a bearer instrument for whoever sees
it first. Including the outputs in the digest is what makes a signature an
authorization of a specific payment.

*Tests: `tests/test_transaction.cpp` — `SignatureCommitsToOutputs`,
`SignatureCommitsToOutputAmount`, `SignatureCommitsToTraceabilityFields`.*

### 6.3 Validation

```
outputs non-empty
∧ (coinbase ? no inputs ∧ exactly one positive output
            : inputs non-empty
              ∧ POT holds
              ∧ all outputs positive
              ∧ Σ inputs = Σ outputs + fee
              ∧ every signature verifies against sighash)
```

Amount equality uses a tolerance of 1e-9 — an order of magnitude below one
satoshi of GXC (1e-8) — because amounts are carried as doubles.

---

## 7. Proof of Traceability

### 7.1 The rule

For every transaction *Tᵢ* that is neither a coinbase nor genesis:

```
Tᵢ.inputs[0].txHash  =  Tᵢ.prevTxHash
Tᵢ.inputs[0].amount  =  Tᵢ.referencedAmount        (within 1e-9)
```

Both conjuncts are required. `prevTxHash` may be neither empty nor `"0"`: a
transaction that spends something must say what it descends from.

### 7.2 What it buys

Given any transaction, `prevTxHash` names its ancestor; that ancestor's
`prevTxHash` names *its* ancestor; and so on until a coinbase, which is exempt
because it has no ancestor. The declaration is inside the signed message
(Section 6.2), so it cannot be rewritten after the fact without invalidating the
signature. The result is a chain of custody that is checked at block-validation
time rather than reconstructed later by clustering heuristics.

`Blockchain::initializeTraceability()` builds a forward index over this relation
at startup, which is what makes descendant queries — and therefore taint
propagation (Section 11) — tractable.

### 7.3 Verification is strict; normalization is separate

A wallet that knows nothing about POT can build a transaction, call
`Transaction::normalizeTraceability()` to populate the fields from `inputs[0]`,
and sign. Verification never does this. The distinction is the entire mechanism:

> An earlier revision substituted `inputs[0].txHash` for an unset `prevTxHash`
> *inside the verifier* and then compared the two. The comparison was between a
> value and itself and could not fail. The same applied to the amount. POT
> reported success on precisely the transactions that had never established a
> chain link — the ones it existed to catch.

A convenience applied at construction time is a convenience. The same
convenience applied at validation time is the absence of a rule.

Relatedly, `isGenesis()` requires that a transaction have *no inputs*. It
short-circuits every traceability check, so without that condition any
transaction could opt out of POT by declaring `prevTxHash = "0"` while still
spending real coins.

*Source: `src/Transaction.cpp`, `src/Blockchain.cpp`.
Tests: `tests/test_traceability.cpp` — `MissingAncestorIsRejected`,
`MismatchedAncestorIsRejected`, `MismatchedReferencedAmountIsRejected`,
`ChainOfCustodyWalksBackToCoinbase`, `BrokenLinkInTheMiddleIsDetected`.*

---

## 8. The Proof-of-Work Receipt

### 8.1 Definition

```
receipt(B) = SHA256( prevHash ‖ merkleRoot ‖ nonce ‖ minerPubKey ‖ difficulty ‖ timestamp )
```

### 8.2 The binding

A PoW block is valid only if:

1. `receipt` stored on the block equals `receipt(B)` recomputed from its header;
2. **every** coinbase in the block carries that same receipt;
3. every coinbase declares `blockHeight = B.index`.

PoS blocks mint no mining reward and must carry no receipt.

Checking *every* coinbase rather than only `transactions[0]` closes the case
where a block smuggles a second coinbase further down the list.

### 8.3 What it proves

Because the receipt commits to the nonce, it identifies one specific
proof-of-work solution. Because it commits to the merkle root, it cannot be
carried onto a different transaction set. Because the coinbase must repeat it
along with the height, a minted coin carries a pointer to the work that minted
it — and that pointer is checked, so it cannot be fabricated.

Composed with POT, the two give an end-to-end audit path: from any spend, follow
`prevTxHash` back to a coinbase; from that coinbase, read the receipt; recompute
it from the block header; confirm the header hash meets the target it claims.
Every step is a check a node already performs.

*Source: `src/block.cpp` (`computeWorkReceipt`, `verifyWorkReceipt`),
`src/Blockchain.cpp` (`validateWorkReceipt`).
Tests: `tests/test_traceability.cpp` — `WorkReceipt.*` and
`MintedCoinsAreTraceableFromSpendToWork`.*

---

## 9. Monetary policy

```
R(h) = 50 / 2^⌊h / 1,051,200⌋      GXC
```

- Initial reward: **50 GXC**
- Halving interval: **1,051,200 blocks** (~4 years at 600 s)
- Maximum supply: **31,000,000 GXC**, enforced as a hard cap — the final reward
  is truncated so the cap is never exceeded.

Two adjustments apply on top of the base schedule
(`Blockchain::calculateBlockReward`):

- a difficulty bonus of up to **+10%**, scaled as `min(0.1, (D−1)/100)`;
- transaction fees, split between the miner and the system pool, with the pool
  share configurable via `fee_pool_split_percentage` (default **15%**).

The system pool funds the reversal fee pool (Section 12).

---

## 10. Staking and validator selection

Selection is stake-weighted with a concave time bonus:

```
w(v) = stake(v) × (days(v) / 365)^β        β = 0.5

P(v selected) = w(v) / Σ_u w(u)
```

The square root means a longer lock increases weight but with diminishing
returns, so committing capital for longer is rewarded without making very long
locks dominate outright.

| Parameter | Value |
|---|---|
| Minimum validator stake | 100 GXC |
| Minimum staking period | 14 days |
| Maximum staking period | 365 days |
| Time-weight exponent β | 0.5 |
| Minimum pool contribution | 10 GXC |

A PoS block is signed by the selected validator over the PoS header commitment,
which excludes the nonce (there is no search) and includes the validator address
(so a signature is bound to the validator that produced it and cannot be replayed
onto another block).

*Source: `src/Validator.cpp`, `src/SalectValidator.cpp`, `src/StakingPool.cpp`.
Tests: `tests/test_block.cpp` — `PosSignatureVerifies`,
`PosSignatureFromWrongValidatorIsRejected`,
`PosSignatureDoesNotTransferBetweenBlocks`.*

---

## 11. Taint propagation and fraud detection

When a transaction is reported stolen it is seeded with taint τ = 1.0. Taint
flows to descendants proportionally to value:

```
τ(T_j) = Σ_i  w_i · τ(T_i)        where  w_i = value_from_T_i / total_input_value
```

Because the weights are value shares summing to at most 1, taint is conserved and
never amplifies: splitting stolen funds across many outputs divides the taint
among them rather than multiplying it.

Propagation is a breadth-first walk over the POT descendant index, bounded by a
maximum hop count (default 10) and stopping when τ falls below δ = 0.1.

Five detection rules run against tainted transactions:

| Rule | Condition |
|---|---|
| Velocity anomaly | Tainted value moving faster than a normal-use baseline |
| Fan-out | Tainted value split across an unusually large number of outputs |
| Re-aggregation | Previously split tainted value recombining, θ = 0.7 |
| Dormancy activation | A long-dormant tainted output suddenly moving |
| Clean-zone entry | Tainted value reaching a registered exchange, staking pool, merchant, or validator |

Thresholds: τ ≥ 0.5 is high, τ ≥ 0.8 is critical.

The clean-zone registry (`src/AddressRegistry.cpp`) is what makes the last rule
useful: it marks the boundaries where stolen value would exit into the regulated
economy, which is where an alert has time to matter.

*Source: `src/FraudDetection.cpp`, `src/AddressRegistry.cpp`.*

---

## 12. The reversal pipeline

A reversal moves funds from a taint-flagged holder back toward the victim. It is
deliberately **not** trustless, and it is worth being precise about who is
trusted rather than implying otherwise.

The pipeline:

1. **Report.** A victim files a fraud report identifying the stolen transaction.
2. **Taint.** Propagation (Section 11) establishes which downstream outputs
   carry stolen value, and in what proportion.
3. **Proof of Feasibility (POF).** `ProofGenerator` produces a signed artifact
   asserting that the traced funds exist, are unspent, and are attributable to
   the reported theft with a stated taint score.
4. **Approval.** Administrators in `MarketMakerAdmin` review the POF. Approval
   is multi-party and role-gated; a single administrator cannot execute a
   reversal.
5. **Execution.** `ReversalExecutor` constructs a `REVERSAL` transaction, which
   is subject to the same validation as any other.
6. **Fees.** `ReversalFeePool` funds the process from the system pool share of
   transaction fees, so recovery does not depend on the victim's ability to pay.

**Trust statement.** The administrative set can, by colluding at the required
threshold, move funds that taint analysis has flagged. That is a real power and
this document does not describe it as anything else. The mitigations are that
every step leaves an on-chain record, taint scores are independently
recomputable by any node from public data, and the POF is a signed artifact that
can be checked after the fact. Whether that is an acceptable trade is a matter
of governance, not cryptography, and prospective users should decide
deliberately.

*Source: `src/ProofGenerator.cpp`, `src/ReversalExecutor.cpp`,
`src/ReversalFeePool.cpp`, `src/MarketMakerAdmin.cpp`.*

---

## 13. Network protocol

- **Protocol version:** 70015
- **Ports:** P2P 9333 (testnet 19333), RPC 8332 (testnet 18332), REST/WS 8080 (testnet 18080)
- **Maximum connections:** 125
- **Maximum block size:** 1,048,576 bytes

Blocks and transactions are framed as `<length>:<bytes>` fields. Every decoder
validates the declared length against the bytes actually remaining before
reading, so a truncated or hostile frame is rejected rather than read out of
bounds. List payloads additionally bound the element count by the remaining
buffer size.

APIs: JSON-RPC 2.0 (`getblockcount`, `getblock`, `gettransaction`, `getbalance`,
`sendtoaddress`, `getmininginfo`, `validateaddress`, `getstakinginfo`, …), a REST
surface under `/api/`, a WebSocket stream for block/transaction/stats events, and
Stratum for pool mining.

*Source: `src/MessageHandler.cpp`, `src/P2PNetwork.cpp`, `src/RPCAPI.cpp`,
`src/RESTServer.cpp`, `src/WebSocketServer.cpp`, `src/Stratum.cpp`.
Tests: `tests/test_block.cpp` — `BlockSerialization.*`, including
`RejectsTruncatedPayload` and `RejectsOversizedLengthPrefix`.*

---

## 14. Storage

LevelDB, with namespaced key prefixes: blocks by hash and by height, transactions
by hash, the UTXO set, validators, stakes, governance proposals and votes, token
balances, bridge transfers, oracle submissions, taint records, fraud reports,
reversal records, admin roles and sessions, and chain metadata. Writes that must
be atomic go through batched writes.

*Source: `src/Database.cpp`.*

---

## 15. Subsystems built on the core

| Subsystem | What it does | Source |
|---|---|---|
| Gold token (GXC-G) | Reserve-backed token with auditable reserve accounting | `src/tokens/GoldToken.cpp` |
| Stock contracts | Three models: synthetic (price-tracking), custodial-backed (1:1 shares held), issuer-authorized (cap-table reflecting) | `src/tokens/StockContract.cpp`, `src/StockContractModels.cpp` |
| Governance | Stake-weighted proposals and voting; default quorum 15%, pass threshold 60%, 7-day voting period | `src/governance/` |
| Proof of Price | Multi-oracle price consensus with submission quorum and staleness bounds | `src/ProofOfPrice.cpp` |
| Cross-chain bridge | Multi-signature transfers across supported chains | `src/CrossChainBridge.cpp` |
| Security engine | Hashrate monitoring and adaptive difficulty response | `src/security/SecurityEngine.cpp` |
| Mining | SHA-256, Ethash, GXHash; hardware detection, pool management, Stratum | `src/mining/` |

These are functional but carry substantially less test coverage than the
consensus core. Treat them accordingly.

---

## 16. Security analysis

**51% attack.** Fork choice is by accumulated chainwork, so an attacker must
out-work the honest chain rather than out-count it. The hybrid design raises the
bar further: rewriting a segment containing PoS blocks requires the corresponding
validator keys in addition to hashpower.

**Double-spend.** Every input is checked against the live UTXO set at the claimed
amount before a block is accepted; a spent output is simply absent.

**Forged proof-of-work.** Prevented by recomputing both the merkle root and the
header hash from the block's own contents during validation, so a declared hash
that the contents do not produce is rejected.

**Transaction malleation.** Signatures cover all outputs and the POT fields
(Section 6.2), so a relayed transaction cannot be redirected or re-parented.

**Receipt transplantation.** The work receipt commits to the nonce and merkle
root, so a valid receipt from one block does not verify on another.

**Grinding the difficulty claim.** A block declaring a lower difficulty than the
network requires is rejected by the difficulty check; one declaring a higher
difficulty must actually meet the harder target.

**Hostile P2P input.** All length-prefixed reads are bounds-checked against the
remaining buffer. The test suite runs clean under AddressSanitizer and
UndefinedBehaviorSanitizer in CI.

---

## 17. Known limitations

Stated plainly, because a whitepaper that only lists strengths is not useful.

1. **No external audit.** No third party has reviewed this code. The defects
   found and fixed during the most recent internal review included a
   proof-of-work check that no block could pass, a traceability check that could
   not fail, a signature that did not cover its own outputs, and a Keccak-256
   that was not Keccak-256. Assume more remain.

2. **Addresses have no checksum.** A typo produces a valid-looking address and
   unrecoverable loss. This needs a Base58Check or Bech32 encoding before any
   real value moves.

3. **Amounts are `double`.** IEEE-754 doubles hold integers exactly only to
   2⁵³; at 1e-8 granularity that is about 90 million GXC — above the 31 million
   cap, so current parameters stay inside the exact range. It is nonetheless the
   wrong representation for money, and comparisons need an epsilon everywhere.
   Integer satoshis are the correct fix.

4. **Signature malleability.** DER signatures are not canonicalized and low-S is
   not enforced, so a third party can produce a different-but-valid encoding of
   the same signature and change the transaction id.

5. **Ethash is not Ethereum's Ethash.** The implementation follows the structure
   but operates on hex-string representations and a reduced cache, and does not
   produce Ethereum-compatible results. It is a distinct memory-hard function
   and should be described as such, not as GPU-compatible Ethash.

6. **Reversal is administratively trusted.** See Section 12.

7. **Subsystem coverage is uneven.** The consensus core, transactions, POT, work
   receipts, and serialization are covered by tests. Governance, the bridge, the
   oracle, and the token contracts are substantially less so.

8. **PoS validator-set security is not fully analyzed.** Long-range attacks,
   nothing-at-stake mitigation, and slashing are not addressed by the current
   implementation.

9. **OpenSSL 3.x migration is outstanding.** Signing uses the deprecated
   low-level `EC_KEY` interface. It works, but should move to `EVP_PKEY`.

---

## 18. Parameter reference

| Parameter | Mainnet | Testnet |
|---|---|---|
| P2P port | 9333 | 19333 |
| RPC port | 8332 | 18332 |
| REST / WebSocket port | 8080 | 18080 |
| Target block time | 600 s | 120 s |
| Difficulty retarget interval | 2016 blocks | 2016 blocks |
| Minimum difficulty | 1000.0 | 1.0 |
| Maximum difficulty | 10,000,000 | 10,000 |
| powLimit (compact) | `0x1d00ffff` | `0x207fffff` |
| Initial block reward | 50 GXC | 50 GXC |
| Halving interval | 1,051,200 blocks | 1,051,200 blocks |
| Maximum supply | 31,000,000 GXC | 31,000,000 GXC |
| Address prefix | `GXC` | `tGXC` |
| Maximum block size | 1,048,576 B | 1,048,576 B |
| Maximum connections | 125 | 125 |
| Protocol version | 70015 | 70015 |
| Minimum validator stake | 100 GXC | 100 GXC |
| Staking period | 14–365 days | 14–365 days |
| Time-weight exponent β | 0.5 | 0.5 |
| Taint cutoff δ | 0.1 | 0.1 |
| High / critical taint | 0.5 / 0.8 | 0.5 / 0.8 |
| Re-aggregation threshold θ | 0.7 | 0.7 |
| Governance quorum | 15% | 15% |
| Governance pass threshold | 60% | 60% |
| Voting period | 7 days | 7 days |
| Fee pool split | 15% | 15% |
| GXHash Argon2id | 64 MiB, t=3, p=4 | 64 MiB, t=3, p=4 |

---

## 19. Verifying the claims in this document

Nothing above needs to be taken on trust. Build the tree and run the suite:

```bash
sudo apt-get install -y build-essential cmake pkg-config \
    libssl-dev libleveldb-dev libsnappy-dev

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build --parallel
cd build && ctest --output-on-failure
```

To exercise the mechanisms this paper is named for:

```bash
./build/gxc-tests Traceability    # Proof of Traceability, chain of custody
./build/gxc-tests WorkReceipt     # Proof-of-Work Receipt binding
./build/gxc-tests ProofOfWork     # target predicate, miner/validator agreement
```

Each test states in its own comment which invariant it protects and, where it is
a regression test, what went wrong before.

---

## Document status

Derived from the implementation at the commit that introduced it. Where this
document and the code disagree, the code is authoritative and the discrepancy is
a bug in this document — please open an issue.

**License:** MIT, as with the rest of the repository.
