# GXC-CORE Architecture Guide

## Overview

GXC-CORE is a C++17 implementation of the GoldXCoin blockchain, featuring hybrid PoW/PoS consensus, multi-algorithm mining, advanced fraud detection with transaction reversal, gold-backed tokens, and an AI-driven security engine.

```
                          ┌─────────────────────────────┐
                          │        Applications          │
                          │  CLI  │  GUI  │  Miner  │    │
                          └────────────┬────────────────┘
                                       │
                          ┌────────────▼────────────────┐
                          │         API Layer            │
                          │  RPC  │  REST  │  WebSocket  │
                          │       │  Stratum (Mining)    │
                          └────────────┬────────────────┘
                                       │
           ┌───────────────────────────▼───────────────────────────┐
           │                   Core Engine                         │
           │                                                       │
           │  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐ │
           │  │  Blockchain  │  │   Consensus   │  │   Wallet    │ │
           │  │  (Chain Mgmt)│  │  (PoW + PoS)  │  │ (Key Mgmt) │ │
           │  └──────┬───────┘  └──────┬────────┘  └─────────────┘ │
           │         │                 │                            │
           │  ┌──────▼───────┐  ┌──────▼────────┐  ┌────────────┐ │
           │  │ Fraud Detect │  │   Security    │  │  Staking   │ │
           │  │ (Taint/POT)  │  │   Engine (AI) │  │   Pool     │ │
           │  └──────┬───────┘  └───────────────┘  └────────────┘ │
           │         │                                             │
           │  ┌──────▼───────┐  ┌───────────────┐  ┌────────────┐ │
           │  │   Reversal   │  │  Governance   │  │ Gold Token │ │
           │  │  (POF/Exec)  │  │ (Vote/Propose)│  │ (GXC-G)   │ │
           │  └──────────────┘  └───────────────┘  └────────────┘ │
           └───────────────────────────┬───────────────────────────┘
                                       │
           ┌───────────────────────────▼───────────────────────────┐
           │                Infrastructure                         │
           │  ┌──────────┐  ┌──────────┐  ┌─────────┐  ┌───────┐ │
           │  │ Database  │  │ Network  │  │ Crypto  │  │ Config│ │
           │  │ (LevelDB) │  │  (P2P)   │  │(OpenSSL)│  │       │ │
           │  └──────────┘  └──────────┘  └─────────┘  └───────┘ │
           └───────────────────────────────────────────────────────┘
```

---

## Module Descriptions

### 1. Blockchain Core

**Files:** `src/Blockchain.cpp`, `include/blockchain.h`

The central module managing the chain state, block validation, UTXO tracking, and transaction processing.

**Responsibilities:**
- Chain initialization and genesis block creation
- Block addition and validation
- UTXO set management
- Transaction pool (mempool)
- Difficulty adjustment (integrated with Security Engine)
- Halving schedule (50 GXC initial, halving every 1,051,200 blocks)
- Database persistence and recovery

**Key Design Decisions:**
- Mutex-protected chain access (`chainMutex`) for thread safety
- Database lock file prevents accidental chain rebuilds
- Ephemeral storage detection warns operators about data loss risks

### 2. Consensus Engine

**Hybrid PoW/PoS Model:**

The chain alternates between Proof-of-Work and Proof-of-Stake blocks, combining the security guarantees of both mechanisms.

#### Proof of Work (3 Algorithms)

| Algorithm | Target Hardware | File |
|-----------|----------------|------|
| SHA-256 | ASICs, general CPUs | `src/mining/SHA256Miner.cpp` |
| Ethash | GPUs (DAG-based) | `src/mining/EthashMiner.cpp` |
| GXHash | ASIC-resistant | `src/mining/GXHashMiner.cpp` |

Each PoW block includes a `workReceiptHash` binding the mining work to the specific block reward, preventing reward-stealing attacks.

#### Proof of Stake

**Validator Selection:** Weighted-stake formula:
```
w_i = stake_i * (days_i / 365)^0.5
```
where `beta = 0.5` provides a square-root time bonus. This prevents short-term stake-and-dump attacks while rewarding long-term participation.

**Files:** `src/Validator.cpp`, `src/SalectValidator.cpp`, `src/StakingPool.cpp`

**Parameters:**
- Minimum stake: 100 GXC
- Lockup: 14-365 days
- Slashing: Enabled for double-signing and extended downtime

### 3. Cryptographic Primitives

**File:** `src/Crypto.cpp`, `include/Crypto.h`

| Primitive | Usage | Library |
|-----------|-------|---------|
| secp256k1 ECDSA | Key generation, signing, verification | OpenSSL |
| SHA-256 / SHA-256d | Block hashing (PoW), transaction IDs | OpenSSL |
| Keccak-256 | Contract hashing, Ethash compatibility | OpenSSL EVP |
| RIPEMD-160 | Address generation (with SHA-256) | OpenSSL |
| Blake2b | General cryptographic hashing | Custom impl |
| Argon2id | Password/key derivation | Custom impl |

**Address Format:**
```
Mainnet: GXC + RIPEMD160(SHA256(pubkey))[0:34]
Testnet: tGXC + RIPEMD160(SHA256(pubkey))[0:34]
```

### 4. Fraud Detection System (Proof of Traceability)

**Files:** `src/FraudDetection.cpp`, `include/FraudDetection.h`

The Proof of Traceability (POT) system tracks the flow of stolen funds through the transaction graph using mathematical taint propagation.

#### Taint Propagation Algorithm

```
tau(T_j) = SUM( w_i * tau(T_i) )

where:
  w_i = value_from_T_i / total_input_value
  tau(T_stolen) = 1.0  (seed transaction)
  Stop when tau < delta (0.1 threshold)
```

The algorithm uses BFS traversal with configurable `maxHops` to limit computational cost. It is `O(edges touched)`, not `O(chain size)`.

#### Detection Rules

| # | Rule | Threshold | Description |
|---|------|-----------|-------------|
| 1 | Velocity Anomaly | epsilon = 300s | Rapid fund movement between transactions |
| 2 | Fan-Out Pattern | K = 5 outputs | Smurfing/coin mixing detection |
| 3 | Re-Aggregation | theta = 0.7 | Layering - recombining split funds |
| 4 | Dormancy Activation | 7 days | Long-dormant funds suddenly moving |
| 5 | Clean Zone Entry | Any taint | Tainted funds entering exchanges/staking |

#### Alert Levels

| Level | Taint Score | Rule Violations |
|-------|-------------|-----------------|
| CRITICAL | >= 0.8 | >= 3 |
| HIGH | >= 0.5 | >= 2 |
| MEDIUM | >= 0.1 | >= 1 |
| LOW | < 0.1 | 0 |

### 5. Transaction Reversal System

**Files:** `src/ReversalExecutor.cpp`, `src/ProofGenerator.cpp`, `include/ReversalExecutor.h`

The reversal system allows recovery of stolen funds through cryptographic proofs and a two-phase validation model.

#### Design Principle: Separation of Authority

```
Admin Approval (Human)          Protocol Validation (Code)
├── Verifies fraud occurred     ├── Cryptographic proof valid
├── Identifies victim           ├── Taint score > 0.1
├── Authorizes recovery         ├── Holder has sufficient balance
└── Signs approval              ├── Fee pool has funds
                                ├── Within 30-day time window
                                └── Mathematical constraints met
```

Admin approval validates **facts** (was there fraud?). Protocol validates **feasibility** (is reversal safe?).

#### Execution Flow

1. Admin generates and signs `ProofOfFeasibility`
2. Protocol validates 5 mathematical constraints
3. Create reversal transaction
4. Debit current holder
5. Credit original victim
6. Deduct fee from system pool
7. Add to blockchain
8. Mark original tx as reversed (prevents double-reversal)
9. Deposit 0.2% execution fee back to pool (self-sustaining)

### 6. AI Security Engine

**Files:** `src/security/SecurityEngine.cpp`, `include/security/SecurityEngine.h`

Six-layer protection system that operates on every block:

```
Layer 1: AI Hashrate Sentinel
  └── Exponential smoothing: predicted = 0.60*current + 0.40*previous
  └── Maintains rolling history for trend detection

Layer 2: Predictive Difficulty Guard
  └── Adjusts difficulty based on predicted vs actual hashrate
  └── Surge threshold: 12% jump triggers increase
  └── Attack threshold triggers 2x difficulty

Layer 3: Staker-Balance Modifier
  └── Higher stake participation = slightly higher PoW difficulty
  └── influence = clamp(stakeRatio * 0.20, 0, 0.50)

Layer 4: Emission Guard
  └── Fast blocks get reduced rewards (anti-gaming)
  └── >3 consecutive fast blocks trigger exponential penalty
  └── reward = baseReward * clamp(timeTaken/targetTime, 0.1, 1.5)

Layer 5: Fee Surge Guard
  └── Scales fees based on mempool congestion
  └── Range: 0.001 GXC (min) to 0.01 GXC (max)

Layer 6: Hybrid Penalty Logic
  └── Enforces 50/50 PoW/PoS balance
  └── >30% imbalance reduces dominant type rewards
```

**Attack Detection:**
- `FAST_BLOCK_ATTACK`: Block time < 10% of target, >5 consecutive
- `HASHRATE_SURGE_ATTACK`: Hashrate surge exceeds attack threshold
- `SELFISH_MINING_DETECTED`: Block time > 10x target, >3 consecutive

### 7. Token Systems

#### Gold-Backed Tokens (GXC-G)

**Files:** `src/tokens/GoldToken.cpp`, `include/GoldToken.h`

100% gold-reserve-backed tokens verified through the Proof of Price oracle system.

#### Tokenized Stock Contracts

**Files:** `src/tokens/StockContract.cpp`, `include/StockContract.h`

Supports synthetic, custodial, and issuer-authorized equity tokens.

### 8. Governance

**Files:** `src/governance/Governance.cpp`, `src/governance/Proposals.cpp`, `src/governance/Voting.cpp`

On-chain governance with stake-weighted voting:
- Proposal creation with configurable fees
- Quorum: 51% of stake-weighted votes
- Supported proposal types: parameter changes, upgrades, treasury

### 9. Network Layer

**Files:** `src/Network.cpp`, `src/P2PNetwork.cpp`, `src/PeerManager.cpp`, `src/MessageHandler.cpp`

```
┌────────────┐     ┌────────────┐     ┌────────────┐
│   Peer A   │◄───►│   Peer B   │◄───►│   Peer C   │
│  P2P:8333  │     │  P2P:8333  │     │  P2P:8333  │
└────────────┘     └────────────┘     └────────────┘

Message Types: handshake, ping/pong, block, transaction
Max Peers: 125 (configurable)
Health Check: 30-second intervals, 2-minute timeout
```

### 10. Database Layer

**File:** `src/Database.cpp`, `include/Database.h`

LevelDB-based persistence with 14 key namespaces:

| Prefix | Data Type |
|--------|-----------|
| `blk:` | Block data |
| `blkh:` | Block by height index |
| `tx:` | Transaction data |
| `txb:` | Transaction-to-block mapping |
| `utxo:` | Unspent transaction outputs |
| `val:` | Validator records |
| `peer:` | Known peers |
| `cfg:` | Configuration |
| `trace:` | Traceability data |
| `addr:` | Address index |
| `pending:` | Mempool transactions |
| `gold:` | Gold reserve records |
| `reversal:` | Reversal tracking |
| `staking:` | Staking pool state |

**Safety Features:**
- Mainnet/testnet network isolation (prevents cross-contamination)
- Atomic write batches
- Lock file to prevent accidental rebuilds
- Ephemeral storage detection

### 11. API Layer

| Protocol | Port | Purpose |
|----------|------|---------|
| JSON-RPC 2.0 | 8332 (18332 testnet) | Node control, wallet ops |
| REST | 8080 | Block explorer, public queries |
| WebSocket | 8081 | Real-time event streaming |
| Stratum | Configurable | Pool mining protocol |

---

## Data Flow

### Transaction Lifecycle

```
1. Wallet creates transaction
   └── UTXO selection, fee calculation, traceability linking

2. Transaction signed (ECDSA secp256k1)
   └── Each input signed with sender's private key

3. Submitted to mempool
   └── Validation: signatures, UTXO existence, balance, traceability

4. Fraud Detection check
   └── Taint score calculation, rule evaluation
   └── Block if taint >= CRITICAL or address flagged

5. Included in next block by miner/validator
   └── PoW: Mining with selected algorithm
   └── PoS: Validator selected by weighted-stake formula

6. Block validated by network
   └── Security Engine evaluation (6 layers)
   └── Consensus rules check

7. Block added to chain
   └── UTXO set updated
   └── Database persisted
   └── Broadcast to peers
```

### Block Production

```
PoW Block:                          PoS Block:
┌─────────────────────┐            ┌─────────────────────┐
│ Select algorithm    │            │ Weight calculation   │
│ (SHA256/Ethash/GXH) │            │ w = stake*(days/365) │
├─────────────────────┤            ├─────────────────────┤
│ Mine (find nonce)   │            │ Select validator    │
│ hash < target       │            │ (weighted random)   │
├─────────────────────┤            ├─────────────────────┤
│ Security Engine     │            │ Security Engine     │
│ evaluate block      │            │ evaluate block      │
├─────────────────────┤            ├─────────────────────┤
│ Emission Guard      │            │ Hybrid penalty      │
│ (adjust reward)     │            │ check               │
├─────────────────────┤            ├─────────────────────┤
│ Add to chain        │            │ Add to chain        │
│ Broadcast           │            │ Broadcast           │
└─────────────────────┘            └─────────────────────┘
```

---

## Build System

```
CMake 3.16+ (C++17, no GNU extensions)

Targets:
  gxc-node        Main blockchain node
  gxc-cli         Command-line interface
  gxc-keygen      Key generation utility
  gxc-miner       Standalone miner (SHA256/Ethash/GXHash)
  gxc-miner-gui   GUI miner (Qt-based)
  gxc-explorer    Block explorer
  gxc-netdiag     Network diagnostic tool
  gxc-pool-proxy  Mining pool proxy

Dependencies:
  OpenSSL >= 1.1   Cryptography
  LevelDB          Database
  Snappy           Compression
  pthreads         Threading
  Qt5 (optional)   GUI components
```

---

## Network Parameters

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| P2P Port | 8333 | 18333 |
| RPC Port | 8332 | 18332 |
| Block Time Target | 600s (10 min) | 120s (2 min) |
| Difficulty Retarget | 2,016 blocks | 2,016 blocks |
| Initial Block Reward | 50 GXC | 50 GXC |
| Halving Interval | 1,051,200 blocks | 1,051,200 blocks |
| Max Supply | 31,000,000 GXC | 31,000,000 GXC |
| Address Prefix | `GXC` | `tGXC` |
| Network Magic | `GXC\x01` | `GXCT` |
| Max Block Size | 1 MB | 1 MB |
| Protocol Version | 70015 | 70015 |
