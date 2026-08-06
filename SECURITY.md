# Security Policy

## Project status

GXC-CORE is **pre-launch**. No mainnet is running, there are no tagged releases,
and the code has not been externally audited. Treat the consensus rules as a
specification under review.

The whitepaper's [Known limitations](docs/WHITEPAPER.md#17-known-limitations)
section lists the weaknesses we already know about — addresses without
checksums, `double` amounts, signature malleability, and an administratively
trusted reversal pipeline among them. Reports covering those are still welcome,
but they are known rather than new.

| Branch | Supported |
|---|---|
| `master` | ✅ Security fixes applied |
| Anything else | ❌ Not supported |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately through either channel:

- **GitHub** — [open a private security advisory](https://github.com/ECONX-GROUP-EX-G/GXC_CORE/security/advisories/new) (preferred; it keeps the discussion attached to the repository)
- **Email** — security@goldxcoin.network

Please include:

- A clear description of the vulnerability
- The affected component and file(s)
- Steps to reproduce, ideally a failing test case
- The impact: funds at risk, consensus split, node crash, information disclosure
- A suggested fix, if you have one

We aim to acknowledge within **48 hours** and will agree a disclosure timeline
with you. Credit is given in the release notes unless you would rather stay
anonymous.

## What we consider a vulnerability

Highest priority, in rough order:

1. **Consensus splits** — anything that makes two honest nodes disagree about
   whether a block or transaction is valid.
2. **Forged or bypassed proof-of-work** — accepting a block without the work
   its difficulty implies.
3. **Theft or inflation** — spending coins without the owner's key, minting
   beyond the schedule, or double-spending a UTXO.
4. **Broken provenance** — defeating Proof of Traceability or the
   Proof-of-Work Receipt so that value becomes untraceable, or a minted coin
   cannot be tied to the work that minted it.
5. **Key or signature flaws** — anything affecting ECDSA signing, key
   derivation, or the transaction signature hash.
6. **Remote crashes and resource exhaustion** — reachable from the P2P, RPC,
   REST, or WebSocket surfaces.
7. **Privilege escalation** in the administrative reversal pipeline.

Out of scope: findings that require an attacker to already control the
operator's machine or private keys, and the known limitations listed above.

## Testing safely

Use testnet. It runs with a near-maximal proof-of-work limit, so a single CPU
can produce blocks immediately and you can reproduce most consensus behaviour
locally:

```bash
cmake -S . -B build -DBUILD_TESTS=ON && cmake --build build --parallel
./build/gxc-node --testnet --config config/gxc-testnet.conf
```

A failing case expressed as a test in `tests/` is the most useful form a report
can take — the suite runs without any external framework.

## Security architecture

Layers relevant to a report, and where they live:

| Layer | Implementation |
|---|---|
| Cryptography | secp256k1 ECDSA, SHA-256d, Keccak-256, BLAKE2b, Argon2id, RIPEMD-160 (`src/Crypto.cpp`, `src/Keccak256.cpp`, `src/HashUtils.cpp`) |
| Consensus | Hybrid PoW/PoS, 256-bit targets, chainwork fork choice (`src/Blockchain.cpp`, `src/arith_uint256.cpp`) |
| Provenance | Proof of Traceability and the Proof-of-Work Receipt (`src/Transaction.cpp`, `src/block.cpp`) |
| Fraud detection | Value-weighted taint propagation, five detection rules (`src/FraudDetection.cpp`) |
| Reversal | Proof of Feasibility with multi-party administrative approval (`src/ProofGenerator.cpp`, `src/ReversalExecutor.cpp`, `src/MarketMakerAdmin.cpp`) |
| Hashrate monitoring | Adaptive difficulty response (`src/security/SecurityEngine.cpp`) |
| Network isolation | Separate mainnet/testnet parameters and data directories (`src/Config.cpp`) |

CI runs CodeQL on every push, and the test suite runs under AddressSanitizer
and UndefinedBehaviorSanitizer.
