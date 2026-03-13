# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Active support  |
| 1.x     | ❌ End of life     |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Send a detailed report to: **security@goldxcoin.network**

Include:
- A clear description of the vulnerability
- The affected component and file(s)
- Steps to reproduce
- Potential impact (funds at risk, network disruption, etc.)
- A suggested fix if you have one

We will acknowledge your report within **48 hours** and work with you on a
responsible disclosure timeline. Credit will be given in the release notes
unless you prefer to remain anonymous.

## Security Architecture

GXC-CORE implements multiple layers of security:

1. **Cryptographic Layer** — secp256k1 ECDSA, SHA-256, Keccak-256, Blake2b,
   Argon2id, RIPEMD-160
2. **Quantum-Resistant Cryptography** — CRYSTALS-Dilithium + CRYSTALS-Kyber
   (NIST FIPS 204/203 post-quantum standards)
3. **Consensus Layer** — Hybrid PoW/PoS with multi-algorithm support
4. **Fraud Detection** — Mathematical taint propagation with five detection rules
5. **Reversal System** — Proof of Feasibility with admin/protocol separation
6. **AI Security Engine** — Predictive hashrate sentinel and attack detection
7. **Database Isolation** — Mainnet/testnet network mode guard
8. **Traceability** — Cryptographic transaction chaining (POT)

## Quantum Resistance

GXC-CORE is protected against future quantum computing threats through a
hybrid classical + post-quantum cryptographic architecture.

### The Quantum Threat

Quantum computers running Shor's algorithm can break elliptic curve
cryptography (ECDSA/secp256k1) and RSA in polynomial time. This threatens
all blockchain systems that rely solely on these classical algorithms for
transaction signing, key derivation, and address generation.

### Our Approach: Hybrid Signatures

GXC uses a **"belt and suspenders"** strategy — every transaction is signed
with **both** a classical ECDSA signature **and** a quantum-resistant
CRYSTALS-Dilithium signature. An attacker must break both schemes
simultaneously, which protects against:

- **Quantum attacks** — Even if ECDSA falls, Dilithium remains secure
- **Algorithmic flaws** — Even if a flaw is found in Dilithium, ECDSA
  still protects the transaction

### Algorithms Used

| Algorithm | Standard | Purpose | Security Level |
|-----------|----------|---------|----------------|
| CRYSTALS-Dilithium (Level 3) | NIST FIPS 204 | Digital signatures | 192-bit post-quantum |
| CRYSTALS-Kyber (Kyber768) | NIST FIPS 203 | Key encapsulation | 192-bit post-quantum |
| SHA3-256 | NIST FIPS 202 | Quantum-safe hashing | 128-bit post-quantum |
| SHAKE-256 | NIST FIPS 202 | Extendable output | 256-bit post-quantum |

### Address Formats

Quantum protection is applied at the **signature level**, not the address
level. Every `GXC` address is quantum-safe when the wallet has quantum keys —
there is no need to change your address to be protected.

| Prefix | Type | Quantum Resistant |
|--------|------|-------------------|
| `GXC` | Mainnet | Yes — hybrid signatures protect all GXC addresses |
| `tGXC` | Testnet | Yes — hybrid signatures protect all tGXC addresses |
| `hGXC` | Hybrid mainnet (alternate) | Yes — explicit hybrid address format |
| `htGXC` | Hybrid testnet (alternate) | Yes — explicit hybrid address format |

### Backward Compatibility

- **All `GXC` addresses are quantum-safe** — the same address you already
  use is protected by hybrid signatures (ECDSA + Dilithium) under the hood
- Legacy transactions with classical-only signatures are still accepted
  for backward compatibility during the migration period
- Existing wallets auto-upgrade: `upgradeToQuantumResistant()` adds quantum
  keys while preserving the classical private key and address
- New wallets are created with hybrid keys (classical + quantum) by default

### Key Sizes

| Component | Size |
|-----------|------|
| Dilithium public key | 1,952 bytes |
| Dilithium secret key | 4,000 bytes |
| Dilithium signature | 3,293 bytes |
| Kyber public key | 1,184 bytes |
| Kyber ciphertext | 1,088 bytes |
| Kyber shared secret | 32 bytes |
