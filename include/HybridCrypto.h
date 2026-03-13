#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "Crypto.h"
#include "QuantumCrypto.h"

/**
 * HybridCrypto — Classical + Post-Quantum Hybrid Cryptography
 *
 * Provides a "belt and suspenders" approach to quantum resistance:
 *   - Every key pair contains BOTH a classical secp256k1 key AND a Dilithium key
 *   - Every signature contains BOTH an ECDSA signature AND a Dilithium signature
 *   - Verification requires BOTH signatures to be valid
 *
 * This means:
 *   - If quantum computers break ECDSA → Dilithium still protects you
 *   - If Dilithium is found to have a flaw → ECDSA still protects you
 *   - An attacker must break BOTH schemes simultaneously
 *
 * Address format:
 *   - Mainnet: "hGXC" prefix (hybrid GXC)
 *   - Testnet: "htGXC" prefix (hybrid testnet GXC)
 *
 * Backward compatibility:
 *   - Classical-only transactions are still accepted (graceful migration)
 *   - Hybrid transactions are preferred for new wallets
 *   - The system can validate any signature type
 */

namespace HybridCrypto {

// ============================================================================
// Signature type identifier
// ============================================================================

enum class SignatureType : uint8_t {
    CLASSICAL = 0x01,     // secp256k1 ECDSA only (legacy)
    QUANTUM = 0x02,       // Dilithium only (quantum-only mode)
    HYBRID = 0x03         // ECDSA + Dilithium combined (recommended)
};

// Signature type magic bytes for serialization
static constexpr uint8_t SIG_TYPE_CLASSICAL = 0x01;
static constexpr uint8_t SIG_TYPE_QUANTUM   = 0x02;
static constexpr uint8_t SIG_TYPE_HYBRID    = 0x03;

// ============================================================================
// Hybrid key pair
// ============================================================================

struct HybridKeyPair {
    // Classical (secp256k1) keys
    std::string classicalPrivateKey;  // 32 bytes hex
    std::string classicalPublicKey;   // 33 bytes hex (compressed)

    // Quantum-resistant (Dilithium) keys
    std::string quantumPrivateKey;    // DILITHIUM_SECRET_KEY_SIZE bytes hex
    std::string quantumPublicKey;     // DILITHIUM_PUBLIC_KEY_SIZE bytes hex

    // Combined public key fingerprint (for address generation)
    std::string combinedFingerprint;  // SHA3-256(classicalPubKey || quantumPubKey)
};

// ============================================================================
// Hybrid signature
// ============================================================================

struct HybridSignature {
    SignatureType type;
    std::string classicalSignature;   // ECDSA DER-encoded signature (hex)
    std::string quantumSignature;     // Dilithium signature (hex)

    // Serialize to a single hex string for storage/transmission
    std::string serialize() const;

    // Deserialize from hex string
    static HybridSignature deserialize(const std::string& serialized);
};

// ============================================================================
// Key generation
// ============================================================================

// Generate a hybrid key pair (classical + quantum)
HybridKeyPair generateHybridKeyPair();

// Derive hybrid public keys from private keys
std::string deriveClassicalPublicKey(const std::string& classicalPrivateKeyHex);
std::string deriveQuantumPublicKey(const std::string& quantumPrivateKeyHex);

// ============================================================================
// Signing
// ============================================================================

// Sign with both classical and quantum keys (recommended)
HybridSignature hybridSign(const std::string& data, const HybridKeyPair& keyPair);

// Sign with both keys using separate key strings
HybridSignature hybridSign(const std::string& data,
                           const std::string& classicalPrivateKeyHex,
                           const std::string& quantumPrivateKeyHex);

// Sign with classical key only (legacy compatibility)
HybridSignature classicalSign(const std::string& data, const std::string& classicalPrivateKeyHex);

// Sign with quantum key only
HybridSignature quantumSign(const std::string& data, const std::string& quantumPrivateKeyHex);

// ============================================================================
// Verification
// ============================================================================

// Verify a hybrid signature (checks both classical and quantum)
bool hybridVerify(const std::string& data, const HybridSignature& signature,
                  const std::string& classicalPublicKeyHex,
                  const std::string& quantumPublicKeyHex);

// Verify a serialized signature (auto-detects type)
bool verify(const std::string& data, const std::string& serializedSignature,
            const std::string& classicalPublicKeyHex,
            const std::string& quantumPublicKeyHex);

// Verify classical signature only (for legacy transactions)
bool verifyClassical(const std::string& data, const std::string& signatureHex,
                     const std::string& classicalPublicKeyHex);

// Verify quantum signature only
bool verifyQuantum(const std::string& data, const std::string& signatureHex,
                   const std::string& quantumPublicKeyHex);

// ============================================================================
// Address generation
// ============================================================================

// Generate hybrid address from both public keys
// Format: hGXC<sha3_256(classical_pk || quantum_pk)[:40]> (mainnet)
// Format: htGXC<sha3_256(classical_pk || quantum_pk)[:40]> (testnet)
std::string generateHybridAddress(const std::string& classicalPublicKeyHex,
                                  const std::string& quantumPublicKeyHex,
                                  bool testnet = false);

// Generate hybrid address from a HybridKeyPair
std::string generateHybridAddress(const HybridKeyPair& keyPair, bool testnet = false);

// ============================================================================
// Address validation
// ============================================================================

// Check if an address is a hybrid quantum-resistant address
bool isHybridAddress(const std::string& address);

// Check if an address is a quantum-only address
bool isQuantumAddress(const std::string& address);

// Check if an address is a classical (legacy) address
bool isClassicalAddress(const std::string& address);

// Validate any GXC address format (classical, quantum, or hybrid)
bool isValidGXCAddress(const std::string& address);

// ============================================================================
// Signature type detection
// ============================================================================

// Detect the type of a serialized signature
SignatureType detectSignatureType(const std::string& serializedSignature);

// ============================================================================
// Key serialization for wallet storage
// ============================================================================

// Serialize a hybrid key pair to a storable format
std::string serializeKeyPair(const HybridKeyPair& keyPair);

// Deserialize a hybrid key pair from storage
HybridKeyPair deserializeKeyPair(const std::string& serialized);

// ============================================================================
// Migration utilities
// ============================================================================

// Create a hybrid key pair that incorporates an existing classical private key
// This allows users to keep their ECDSA key while adding quantum protection
HybridKeyPair upgradeClassicalKey(const std::string& existingClassicalPrivateKeyHex);

// Compute the combined fingerprint of classical + quantum public keys
std::string computeCombinedFingerprint(const std::string& classicalPublicKeyHex,
                                       const std::string& quantumPublicKeyHex);

} // namespace HybridCrypto
