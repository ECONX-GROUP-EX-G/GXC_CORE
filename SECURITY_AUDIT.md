# GXC-CORE Security Audit Report

**Project:** GoldXCoin (GXC) Blockchain Node
**Version:** 2.0.0 (Protocol v70015)
**Audit Date:** 2026-03-05
**Scope:** Full codebase review of security-critical components

---

## Executive Summary

This security audit covers the GXC-CORE blockchain implementation, a hybrid PoW/PoS cryptocurrency with advanced fraud detection and transaction reversal capabilities. The audit focused on cryptographic primitives, consensus mechanisms, fraud detection algorithms, network protocol, wallet management, database security, and API attack surfaces.

**Overall Risk Assessment: MODERATE**

The codebase demonstrates strong architectural design with proper separation of concerns, industry-standard cryptographic primitives, and a novel fraud detection system. However, several issues were identified that should be addressed before production deployment.

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 2 | Issues that could lead to fund loss or chain compromise |
| High     | 4 | Issues that could be exploited under specific conditions |
| Medium   | 6 | Issues that weaken security posture |
| Low      | 5 | Best practice improvements |
| Info     | 4 | Observations and recommendations |

---

## 1. Cryptographic Layer (`src/Crypto.cpp`)

### 1.1 [CRITICAL] Keccak-256 Fallback to SHA-256

**File:** `src/Crypto.cpp:288-325`
**Severity:** Critical

The `keccak256()` function silently falls back to SHA-256 if Keccak is unavailable:

```cpp
const EVP_MD* md = EVP_MD_fetch(nullptr, "KECCAK-256", nullptr);
if (!md) {
    md = EVP_sha3_256();  // Fallback 1: SHA3-256 (different from Keccak-256)
    if (!md) {
        return sha256(data);  // Fallback 2: SHA-256 (completely different algorithm)
    }
}
```

**Impact:** If the OpenSSL provider doesn't support Keccak-256, the system silently uses a different hash algorithm. This could cause:
- Transaction hash mismatches between nodes running different OpenSSL versions
- Consensus failures (different nodes computing different hashes for the same data)
- Potential chain splits

**Recommendation:**
- Remove the SHA-256 fallback entirely - fail hard if Keccak-256 is unavailable
- SHA3-256 is NOT Keccak-256 (different padding); this fallback is also incorrect for Ethereum compatibility
- Add startup validation that ensures the required hash algorithm is available

### 1.2 [MEDIUM] No Private Key Validation on Import

**File:** `src/Crypto.cpp:91-144`
**Severity:** Medium

The `derivePublicKey()` function does not validate that the private key is within the valid range for secp256k1 (1 to n-1, where n is the curve order). An out-of-range key could produce undefined behavior.

**Recommendation:** Add range validation before using the private key:
```cpp
// Validate key is in range [1, n-1]
const BIGNUM* order = EC_GROUP_get0_order(group);
if (BN_is_zero(privKey) || BN_cmp(privKey, order) >= 0) {
    throw std::runtime_error("Private key out of valid range");
}
```

### 1.3 [LOW] Address Truncation

**File:** `src/Crypto.cpp:328-346`
**Severity:** Low

Address generation truncates the RIPEMD-160 hash to 34 characters (17 bytes):
```cpp
return prefix + hash160.substr(0, 34);
```

This reduces the address space from 160 bits to 136 bits, slightly increasing collision probability. While still astronomically unlikely, using the full hash would follow Bitcoin best practices.

**Recommendation:** Use the full 40-character RIPEMD-160 hex output or implement Base58Check encoding for shorter, checksummed addresses.

### 1.4 [LOW] Memory Not Zeroed After Key Operations

**File:** `src/Crypto.cpp` (multiple locations)
**Severity:** Low

Private key material in `std::string` objects is not securely zeroed after use. String data may remain in memory after the variable goes out of scope.

**Recommendation:** Use `OPENSSL_cleanse()` on private key buffers before deallocation, or use a secure allocator for key material.

---

## 2. Fraud Detection System (`src/FraudDetection.cpp`)

### 2.1 [HIGH] Taint Calculation Bug - Weight Computed During Accumulation

**File:** `src/FraudDetection.cpp:146-169`
**Severity:** High

The taint calculation has a mathematical error:

```cpp
for (const auto& input : inputs) {
    totalInputValue += input.amount;
    auto it = taintMap.find(input.txHash);
    if (it != taintMap.end()) {
        double weight = input.amount / totalInputValue;  // BUG: totalInputValue is still accumulating
        weightedTaintSum += weight * inputTaint;
    }
}
```

The weight `w_i = input.amount / totalInputValue` is computed while `totalInputValue` is still being accumulated. This means the first input's weight is always 1.0, and subsequent weights are computed against a partial sum rather than the full total.

**Impact:** Taint scores are systematically inaccurate, potentially missing fraud or generating false positives.

**Recommendation:** Calculate `totalInputValue` in a separate first pass, then compute weights in a second pass:
```cpp
double totalInputValue = 0.0;
for (const auto& input : inputs) {
    totalInputValue += input.amount;
}
for (const auto& input : inputs) {
    double weight = input.amount / totalInputValue;
    // ... compute taint
}
```

### 2.2 [MEDIUM] Unbounded Alert Storage

**File:** `src/FraudDetection.cpp:367-396`
**Severity:** Medium

Alerts are stored in memory with no eviction policy:
```cpp
void FraudDetection::addAlert(const FraudAlert& alert) {
    alerts.push_back(alert);
    addressAlerts[alert.address].push_back(alert);
}
```

**Impact:** Over time, this can consume unbounded memory, leading to OOM conditions on long-running nodes.

**Recommendation:** Implement a ring buffer or time-based eviction policy for alerts. Archive old alerts to the database.

### 2.3 [MEDIUM] No Thread Safety in Taint Operations

**File:** `src/FraudDetection.cpp` (entire file)
**Severity:** Medium

The `taintMap`, `stolenTransactions`, `cleanZoneRegistry`, `alerts`, and other data structures have no mutex protection. Since the blockchain processes transactions from multiple threads (network, RPC, mining), concurrent access could cause data corruption.

**Recommendation:** Add `std::shared_mutex` for read-heavy operations on taint data, `std::mutex` for writes.

---

## 3. Reversal Executor (`src/ReversalExecutor.cpp`)

### 3.1 [HIGH] Non-Atomic Reversal Execution

**File:** `src/ReversalExecutor.cpp:161-266`
**Severity:** High

The reversal execution performs multiple steps (debit, credit, fee deduction, blockchain add) without true atomicity. The rollback logic has gaps:

```cpp
// Step 7 failure rollback:
debitAccount(rtx.to, rtx.amount);
creditAccount(rtx.from, rtx.amount);
// Fee is not refunded on blockchain add failure (already deducted from pool)
```

**Impact:** If the blockchain add fails after the fee has been deducted, the fee is permanently lost. Additionally, the debit/credit functions are logging-only placeholders that don't actually modify state, creating a disconnect between the logged operations and actual balance changes.

**Recommendation:**
- Implement a proper transaction journal/WAL (Write-Ahead Log) for reversal operations
- Use database-level atomic batches for all balance modifications
- Ensure fee refund on any failure after fee deduction

### 3.2 [MEDIUM] Placeholder Debit/Credit Functions

**File:** `src/ReversalExecutor.cpp:24-50`
**Severity:** Medium

Both `debitAccount()` and `creditAccount()` are essentially no-ops that only log:
```cpp
bool ReversalExecutor::debitAccount(const std::string& address, uint64_t amount) {
    // Note: In production, this would update UTXO set
    LOG_INFO("Reversal Executor: Debiting ...");
    return true;
}
```

**Impact:** Reversal operations appear to succeed but don't actually move funds at the UTXO level. This is a critical gap for production deployment.

**Recommendation:** Implement actual UTXO modifications or clearly document that reversal execution depends on `blockchain->addReversalTransaction()` for the actual fund movement.

---

## 4. Blockchain Core (`src/Blockchain.cpp`)

### 4.1 [HIGH] Use of Floating-Point for Currency Values

**File:** `src/Blockchain.cpp` and `src/Wallet.cpp` (throughout)
**Severity:** High

Currency amounts are represented as `double` throughout the codebase:
```cpp
double blockReward = 50.0;
double change = availableAmount - amount - fee;
if (change > 0.00000001) { // Epsilon comparison
```

**Impact:** IEEE 754 double-precision floats cannot exactly represent many decimal values (e.g., 0.1). This leads to:
- Rounding errors accumulating over millions of transactions
- Potential for exploitable arithmetic inconsistencies between nodes
- Balance discrepancies that grow over time

**Recommendation:** Use integer arithmetic with satoshi-level precision (1 GXC = 100,000,000 satoshis) throughout, similar to Bitcoin Core's `CAmount` type. The `ReversalExecutor` already uses `uint64_t` for amounts - standardize this pattern.

### 4.2 [MEDIUM] Random Engine Not Cryptographically Secure

**File:** `src/Blockchain.cpp:13`
**Severity:** Medium

The `<random>` header is included, suggesting `std::mt19937` or similar PRNG may be used for validator selection or other consensus-critical operations. Mersenne Twister is NOT cryptographically secure and is predictable given enough output observations.

**Recommendation:** Ensure all consensus-critical randomness uses `RAND_bytes()` from OpenSSL or derive randomness from block hashes.

---

## 5. Wallet Security (`src/Wallet.cpp`)

### 5.1 [CRITICAL] Private Keys Stored in Plaintext

**File:** `src/Wallet.cpp:30-45`
**Severity:** Critical

Wallet private keys are saved to disk as plaintext:
```cpp
bool Wallet::saveToFile(const std::string& filepath) const {
    std::ofstream file(filepath);
    file << privateKey << "\n";
    file << publicKey << "\n";
    file << address << "\n";
}
```

Additionally, the RPC API loads private keys from environment variables (`GXC_WALLET_PRIVATE_KEY` at `src/RPCAPI.cpp:28`), which are visible in `/proc/<pid>/environ` and process listings.

**Impact:** Any user or process with file read access can steal wallet funds. Environment variables are accessible to any process running as the same user.

**Recommendation:**
- Encrypt wallet files using Argon2id-derived keys (the project already includes Argon2id)
- Set restrictive file permissions (0600) on wallet files
- Use file descriptor passing or secure key management instead of environment variables
- Implement wallet unlock/lock with timeout

### 5.2 [HIGH] No File Permission Controls

**File:** `src/Wallet.cpp:30-45`
**Severity:** High

The wallet file is created with default `umask` permissions, which may allow group or world read access depending on the system configuration.

**Recommendation:** Explicitly set file permissions to `0600` (owner read/write only) using `chmod()` after file creation.

---

## 6. Network Layer (`src/Network.cpp`)

### 6.1 [MEDIUM] No Message Size Limits

**File:** `src/Network.cpp:399-426`
**Severity:** Medium

The receive buffer is fixed at 4096 bytes, but there's no protocol-level message framing or size validation:
```cpp
char buffer[4096];
ssize_t bytesReceived = recv(peer.socket, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
```

**Impact:** Messages larger than 4096 bytes will be truncated and parsed incorrectly. Malicious peers could send partial JSON to cause parsing errors.

**Recommendation:** Implement proper message framing with length prefixes and maximum message size enforcement.

### 6.2 [MEDIUM] String-Based Message Parsing

**File:** `src/Network.cpp:428-448`
**Severity:** Medium

Message type detection uses `string::find()` on raw network input:
```cpp
if (message.find("\"type\":\"ping\"") != std::string::npos) {
    handlePingMessage(peer, message);
}
```

**Impact:** This is fragile and potentially exploitable:
- A message containing both `"type":"ping"` and `"type":"block"` would trigger the first match
- No JSON validation before processing
- No authentication on any message type

**Recommendation:** Parse messages as proper JSON first, then dispatch based on the parsed type field. Add message authentication (HMAC or signatures) for critical messages.

### 6.3 [LOW] Mutex Unlock/Lock in `connectToSeedNodes()`

**File:** `src/Network.cpp:381-383`
**Severity:** Low

The method manually unlocks and re-locks the mutex to avoid deadlock:
```cpp
peersMutex.unlock();
connectToPeer(host, port);
peersMutex.lock();
```

**Impact:** This is a race condition. Another thread could modify the `peers` map between the unlock and re-lock, invalidating the iterator.

**Recommendation:** Redesign to avoid holding the mutex while connecting. Collect seed node addresses first, release the lock, then connect.

---

## 7. Database Layer (`src/Database.cpp`)

### 7.1 [LOW] No Input Sanitization for Key Prefixes

**File:** `src/Database.cpp`
**Severity:** Low

Database keys are constructed by concatenating prefixes with user-supplied data (transaction hashes, addresses). While LevelDB is a key-value store without SQL injection risks, malformed keys could collide with other namespaces if the separator is present in the data.

**Recommendation:** Validate that keys don't contain the prefix separator before storage.

### 7.2 [INFO] Singleton Database Pattern

**File:** `src/Database.cpp:18-19`
**Severity:** Info

The Database uses a singleton with `std::mutex` for thread safety. This is appropriate for the single-database architecture but limits testability.

**Recommendation:** Consider dependency injection for easier testing and potential future multi-database scenarios.

---

## 8. Security Engine (`src/security/SecurityEngine.cpp`)

### 8.1 [LOW] Attack Detection Thresholds Are Hardcoded

**File:** `src/security/SecurityEngine.cpp` (throughout)
**Severity:** Low

All security thresholds are compile-time constants:
- `SURGE_THRESHOLD = 0.12`
- `ATTACK_THRESHOLD` (from header)
- `MIN_BLOCK_TIME`, `MAX_DIFFICULTY_CHANGE`

**Impact:** Adjusting thresholds requires recompilation and redeployment. This limits incident response speed.

**Recommendation:** Make critical thresholds configurable via `gxc.conf`, with sane defaults matching the current hardcoded values.

### 8.2 [INFO] Hybrid Penalty Logic Incomplete

**File:** `src/security/SecurityEngine.cpp:230-255`
**Severity:** Info

The `calculateHybridPenalty()` function has unused parameters and a TODO:
```cpp
(void)powRatio; // TODO: Use in reward penalty calculation
```

The `powRatio` is computed but explicitly discarded. The function uses a different `imbalance` calculation that appears correct, but the dead code and TODO suggest incomplete implementation.

**Recommendation:** Remove unused parameters or complete the implementation.

---

## 9. API Security

### 9.1 [HIGH] No Authentication on RPC/REST APIs

**File:** `src/RPCAPI.cpp`, `src/RESTServer.cpp`
**Severity:** High

Neither the RPC API nor REST API implements authentication. The RPC API binds to the configured port without requiring credentials:

**Impact:** Any process on the network can:
- Query blockchain state
- Submit transactions
- Access admin endpoints (fraud detection, reversals)
- Control mining operations

**Recommendation:**
- Implement RPC authentication (username/password as in Bitcoin Core's `rpcuser`/`rpcpassword`)
- Add API key authentication for REST endpoints
- Separate admin endpoints with stronger auth (mutual TLS or signed requests)
- Default to binding on `127.0.0.1` (localhost only)

### 9.2 [INFO] CORS Not Configured

**File:** `src/RESTServer.cpp`
**Severity:** Info

No CORS headers are set on REST API responses.

**Recommendation:** Configure CORS headers appropriately for the deployment scenario. For production, restrict to known frontend origins.

---

## 10. General Findings

### 10.1 [INFO] No Unit Tests in Repository

No test directory or test files were found in the codebase. The `CMakeLists.txt` supports `BUILD_TESTS=ON` but no test source files exist.

**Recommendation:** Add comprehensive test coverage, especially for:
- Cryptographic operations (KAT vectors)
- Taint propagation algorithm correctness
- Consensus validation rules
- Reversal execution edge cases

### 10.2 [LOW] Use of Deprecated OpenSSL APIs

**File:** `src/Crypto.cpp`
**Severity:** Low

The code uses `EC_KEY`, `ECDSA_do_sign`, and `ECDSA_do_verify` which are deprecated in OpenSSL 3.0+. These are still functional but may be removed in future OpenSSL versions.

**Recommendation:** Migrate to the EVP API (`EVP_PKEY`, `EVP_DigestSign`, `EVP_DigestVerify`) for future compatibility.

---

## Remediation Priority

### Immediate (Before Production)
1. **[CRITICAL]** Fix Keccak-256 fallback - remove silent degradation
2. **[CRITICAL]** Encrypt wallet private keys on disk
3. **[HIGH]** Fix taint calculation weight bug
4. **[HIGH]** Implement RPC/REST authentication
5. **[HIGH]** Migrate currency values from `double` to `int64_t` (satoshi units)

### Short-Term (Next Sprint)
6. **[HIGH]** Add file permission controls for wallet files
7. **[HIGH]** Implement atomic reversal execution with WAL
8. **[MEDIUM]** Add thread safety to fraud detection data structures
9. **[MEDIUM]** Implement proper network message framing
10. **[MEDIUM]** Complete debit/credit functions in ReversalExecutor

### Medium-Term (Roadmap)
11. **[MEDIUM]** Replace string-based message parsing with proper JSON
12. **[MEDIUM]** Add alert eviction policy
13. **[MEDIUM]** Validate private key ranges in crypto operations
14. **[LOW]** Migrate to non-deprecated OpenSSL APIs
15. **[LOW]** Make security thresholds configurable
16. **[LOW]** Secure memory handling for key material
17. **[LOW]** Fix `connectToSeedNodes()` race condition

---

## Methodology

This audit was conducted through manual source code review of all security-critical components identified in `CONTRIBUTING.md`:
- `src/Crypto.cpp` - Cryptographic primitives
- `src/FraudDetection.cpp` - Taint propagation algorithm
- `src/ReversalExecutor.cpp` - Fund recovery logic
- `src/Blockchain.cpp` - Block validation and consensus
- `src/Database.cpp` - Persistence layer
- `src/security/SecurityEngine.cpp` - AI attack detection
- `src/Wallet.cpp` - Key management
- `src/Network.cpp` - P2P networking
- `src/RPCAPI.cpp` - JSON-RPC interface
- `src/RESTServer.cpp` - REST API interface

Supporting files (headers, configuration) were also reviewed for context.

---

*This audit is a point-in-time assessment. Changes to the codebase after the audit date may introduce new vulnerabilities or address findings listed here.*
