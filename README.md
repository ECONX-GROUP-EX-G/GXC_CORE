<div align="center">

# GXC-CORE

**A C++17 blockchain node where the provenance of every coin is a consensus rule, not an afterthought.**

[![CI](https://github.com/ECONX-GROUP-EX-G/GXC_CORE/actions/workflows/ci.yml/badge.svg)](https://github.com/ECONX-GROUP-EX-G/GXC_CORE/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ECONX-GROUP-EX-G/GXC_CORE/actions/workflows/codeql.yml/badge.svg)](https://github.com/ECONX-GROUP-EX-G/GXC_CORE/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Tests](https://img.shields.io/badge/tests-173-brightgreen.svg)](tests/)

[Whitepaper](docs/WHITEPAPER.md) · [Architecture](docs/ARCHITECTURE.md) · [API reference](docs/API_REFERENCE.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

> **Status: pre-launch.** No mainnet is running and there has been no external
> audit. The consensus rules are a specification under review. The whitepaper's
> [Known limitations](docs/WHITEPAPER.md#17-known-limitations) section lists what
> is weak — read it before you deploy anything or move real value.

---

## What is different about GXC

Most chains let you *reconstruct* where money came from, after the fact, with
clustering heuristics and off-chain analysis. GXC makes it a rule that nodes
check before a transaction is allowed into a block.

**Proof of Traceability.** Every non-coinbase transaction must declare the
transaction it descends from and the amount it inherited, and both must match its
first input:

```
Tᵢ.inputs[0].txHash  =  Tᵢ.prevTxHash
Tᵢ.inputs[0].amount  =  Tᵢ.referencedAmount
```

The declaration sits inside the signed message, so it cannot be rewritten later.
Follow it backwards from any output and you arrive at the coinbase that minted
the coins — through checks a node already performs.

**The Proof-of-Work Receipt.** Every mined block carries

```
receipt = SHA256( prevHash ‖ merkleRoot ‖ nonce ‖ minerPubKey ‖ difficulty ‖ timestamp )
```

and its coinbase must carry the same receipt plus the block's own height. Because
the receipt commits to the winning nonce and the transaction set, it identifies
one specific proof-of-work solution and cannot be transplanted onto another
block. Newly minted supply is therefore inseparable from the work that justified
minting it.

Together the two give an end-to-end audit path: from any spend, walk
`prevTxHash` back to a coinbase; read its receipt; recompute it from the block
header; confirm the header hash clears the target it claims.

```bash
./build/gxc-tests Traceability   # the chain of custody
./build/gxc-tests WorkReceipt    # the minting binding
```

---

## Everything else

- **Hybrid PoW/PoS consensus** — three proof-of-work algorithms (SHA-256,
  Ethash-style, and Argon2id-based GXHash) and stake-signed PoS blocks on one
  chain, with fork choice by accumulated 256-bit chainwork.
- **Taint propagation** — `τ(Tⱼ) = Σ wᵢ · τ(Tᵢ)`, weighted by value share so
  taint is conserved rather than amplified, with five detection rules and a
  clean-zone registry marking where value would exit into the regulated economy.
- **Administrative reversal pipeline** — taint evidence, a generated Proof of
  Feasibility, and multi-party approval. Deliberately not trustless; the
  whitepaper [says exactly who is trusted](docs/WHITEPAPER.md#12-the-reversal-pipeline).
- **Stake-weighted governance**, a reserve-backed gold token, three models of
  tokenized equity, a multi-oracle price feed, and a multi-signature bridge.

---

## Quick start

### Dependencies

```bash
# Ubuntu / Debian
sudo apt-get install -y build-essential cmake pkg-config \
    libssl-dev libleveldb-dev libsnappy-dev

# macOS
brew install cmake openssl@3 leveldb snappy
```

### Build and test

```bash
git clone https://github.com/ECONX-GROUP-EX-G/GXC_CORE.git
cd GXC_CORE

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build --parallel

cd build && ctest --output-on-failure
```

The tree builds clean under `-Wall -Wextra -Wpedantic`, and CI keeps it that way
with a `-Werror` job. The suite also runs under AddressSanitizer and
UndefinedBehaviorSanitizer on every push.

### Run a node

```bash
# Testnet — near-maximal PoW limit, so a laptop finds blocks immediately
./build/gxc-node --testnet --config config/gxc-testnet.conf

# Mainnet
./build/gxc-node --config config/gxc.conf.example
```

`--help` lists every flag. Configuration keys are documented inline in
[`config/gxc.conf.example`](config/gxc.conf.example); an unrecognized key is
stored but never read, so check spelling against that file.

### Mine

```bash
./build/gxc-sha256-miner --address tGXCyouraddress --threads 4
./build/gxc-ethash-miner --address tGXCyouraddress --gpu 0
./build/gxc-gxhash-miner --address tGXCyouraddress --threads 8
./build/gxc-pool-proxy   --pool pool.example:3333 --address tGXCyouraddress
```

Generate an address first with `./build/gxc-keygen`.

---

## Tests

173 cases across 13 suites, no external test framework required.

```bash
./build/gxc-tests                 # everything
./build/gxc-tests Traceability    # one suite
ctest -R "WorkReceipt|Mining"     # via CTest
```

| Suite | Covers |
|---|---|
| `ArithUint256` | 256-bit arithmetic, compact targets, chainwork accumulation |
| `Hash` / `Merkle` | Known-answer vectors for SHA-256d, Keccak-256, RIPEMD-160; merkle construction |
| `Crypto` | secp256k1 keys, ECDSA sign/verify, address derivation |
| `Transaction` | Structure, balance rules, the signature commitment, serialization |
| `Traceability` | POT accept **and** reject paths, chain-of-custody walks |
| `WorkReceipt` | Receipt determinism, coinbase binding, forgery and transplant rejection |
| `Block` / `BlockSerialization` | Mining, PoS signatures, wire round-trips, hostile input |
| `ProofOfWork` | Target boundary, miner/validator agreement |
| `Mining` | All three algorithms end to end, distinctness, cache reuse, tamper detection |
| `Staking` | Weighting formula, selector statistics, rewards, slashing |
| `Sending` | Payment flows, change, fees, multi-input/output, chained sends |

Tests state the invariant they protect, and regression tests say what went wrong
before — so a failure tells you what broke and why it mattered.

---

## Layout

```
include/          Public headers
src/              Core implementation
  Blockchain.cpp    Chain state, validation, UTXO set
  block.cpp         Block structure, mining, work receipt, serialization
  Transaction.cpp   Transaction model, POT, signature hash
  arith_uint256.cpp 256-bit targets and chainwork
  HashUtils.cpp     Digests, merkle root, the meetsTarget predicate
  Crypto.cpp        secp256k1 ECDSA, addresses
  FraudDetection.cpp Taint propagation, detection rules
  governance/  tokens/  mining/  security/
mining/           Standalone miner entry points
tools/            gxc-cli, keygen, tx builder, explorer, netdiag
tests/            Test suite
docs/             Whitepaper, architecture, API reference
```

| Binary | Purpose |
|---|---|
| `gxc-node` | Full node (mainnet / testnet) |
| `gxc-miner` | Multi-algorithm miner |
| `gxc-sha256-miner` / `gxc-ethash-miner` / `gxc-gxhash-miner` | Dedicated miners |
| `gxc-pool-proxy` | Stratum pool proxy |
| `gxc-cli` | Command-line interface |
| `gxc-keygen` | Key pair and address generator |
| `gxc-tx` | Transaction builder and broadcaster |
| `gxc-explorer` | Local block explorer |
| `gxc-netdiag` | Network diagnostics |

---

## Network parameters

| Parameter | Mainnet | Testnet |
|---|---|---|
| P2P / RPC / REST port | 9333 / 8332 / 8080 | 19333 / 18332 / 18080 |
| Target block time | 600 s | 120 s |
| PoW limit (compact) | `0x1d00ffff` | `0x207fffff` |
| Difficulty floor | 1000.0 | 1.0 |
| Retarget interval | 2016 blocks | 2016 blocks |
| Initial reward · halving | 50 GXC · 1,051,200 blocks | same |
| Maximum supply | 31,000,000 GXC | same |
| Address prefix | `GXC` | `tGXC` |
| Minimum validator stake | 100 GXC | 100 GXC |
| Protocol version | 70015 | 70015 |

Full table, with the taint and governance constants, in the
[whitepaper](docs/WHITEPAPER.md#18-parameter-reference).

---

## APIs

```bash
# JSON-RPC 2.0
curl -X POST http://localhost:8332 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}'

# REST
curl http://localhost:8080/api/block/height/1
curl http://localhost:8080/api/balance/GXCaddress
```

A WebSocket server for streaming block, transaction, and network-stats events is
implemented in `src/WebSocketServer.cpp`, but `gxc-node` does not start it yet —
it currently launches RPC, REST, and P2P only. Same for the Stratum server in
`src/Stratum.cpp`. Wiring both up is [planned work](docs/ARCHITECTURE.md#planned-work).

See [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md).

---

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

Two expectations specific to this codebase:

1. **Consensus changes need rejection tests.** A test showing valid input is
   accepted proves very little. The bugs this project has actually shipped were
   checks that could not fail — a traceability formula that compared a value
   against itself, and a proof-of-work check no block could pass. Show the
   invalid case being rejected.
2. **Keep the build warning-free.** CI enforces `-Werror`.

Good first issues are labelled [`good first issue`](https://github.com/ECONX-GROUP-EX-G/GXC_CORE/labels/good%20first%20issue).

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md)
for private reporting.

## License

MIT — see [LICENSE](LICENSE).
