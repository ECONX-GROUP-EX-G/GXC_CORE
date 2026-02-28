#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <array>

/**
 * QuantumCrypto — Post-Quantum Cryptography for GXC
 *
 * Implements NIST-standardized post-quantum algorithms:
 *   - CRYSTALS-Dilithium (FIPS 204) for digital signatures
 *   - CRYSTALS-Kyber (FIPS 203) for key encapsulation (KEM)
 *   - SHA3-256/SHAKE-256 for quantum-safe hashing
 *
 * Security levels:
 *   - Dilithium3: NIST Level 3 (~192-bit post-quantum security)
 *   - Kyber768:   NIST Level 3 (~192-bit post-quantum security)
 *
 * These algorithms are resistant to attacks by both classical and
 * quantum computers (including Shor's algorithm which breaks ECDSA).
 */

namespace QuantumCrypto {

// ============================================================================
// CRYSTALS-Dilithium Parameters (Level 3 — NIST recommended)
// ============================================================================

// Dilithium3 key/signature sizes (bytes)
static constexpr size_t DILITHIUM_PUBLIC_KEY_SIZE  = 1952;
static constexpr size_t DILITHIUM_SECRET_KEY_SIZE  = 4000;
static constexpr size_t DILITHIUM_SIGNATURE_SIZE   = 3293;

// Dilithium internal parameters (Level 3)
static constexpr int DILITHIUM_K = 6;     // Module dimension
static constexpr int DILITHIUM_L = 5;     // Module dimension
static constexpr int DILITHIUM_ETA = 4;   // Secret key coefficient bound
static constexpr int DILITHIUM_TAU = 49;  // Number of +/-1 in challenge
static constexpr int DILITHIUM_GAMMA1 = (1 << 19);  // y coefficient range
static constexpr int DILITHIUM_GAMMA2 = ((8380417 - 1) / 32);  // Low-order rounding range
static constexpr int DILITHIUM_Q = 8380417;  // Modulus
static constexpr int DILITHIUM_N = 256;      // Polynomial degree
static constexpr int DILITHIUM_D = 13;       // Dropped bits from t

// ============================================================================
// CRYSTALS-Kyber Parameters (Level 3 — Kyber768)
// ============================================================================

static constexpr size_t KYBER_PUBLIC_KEY_SIZE   = 1184;
static constexpr size_t KYBER_SECRET_KEY_SIZE   = 2400;
static constexpr size_t KYBER_CIPHERTEXT_SIZE   = 1088;
static constexpr size_t KYBER_SHARED_SECRET_SIZE = 32;

// Kyber768 internal parameters
static constexpr int KYBER_K_PARAM = 3;    // Module dimension
static constexpr int KYBER_N = 256;        // Polynomial degree
static constexpr int KYBER_Q = 3329;       // Modulus
static constexpr int KYBER_ETA1 = 2;       // CBD parameter
static constexpr int KYBER_ETA2 = 2;       // CBD parameter

// ============================================================================
// Key pair structures
// ============================================================================

struct DilithiumKeyPair {
    std::vector<uint8_t> publicKey;   // DILITHIUM_PUBLIC_KEY_SIZE bytes
    std::vector<uint8_t> secretKey;   // DILITHIUM_SECRET_KEY_SIZE bytes
    std::string publicKeyHex;         // Hex-encoded public key
    std::string secretKeyHex;         // Hex-encoded secret key
};

struct KyberKeyPair {
    std::vector<uint8_t> publicKey;   // KYBER_PUBLIC_KEY_SIZE bytes
    std::vector<uint8_t> secretKey;   // KYBER_SECRET_KEY_SIZE bytes
    std::string publicKeyHex;
    std::string secretKeyHex;
};

struct KyberEncapsulation {
    std::vector<uint8_t> ciphertext;     // KYBER_CIPHERTEXT_SIZE bytes
    std::vector<uint8_t> sharedSecret;   // KYBER_SHARED_SECRET_SIZE bytes
};

// ============================================================================
// CRYSTALS-Dilithium — Digital Signatures
// ============================================================================

// Generate a Dilithium key pair using CSPRNG
DilithiumKeyPair generateDilithiumKeyPair();

// Sign a message using Dilithium
// Returns hex-encoded signature
std::string dilithiumSign(const std::string& message, const std::string& secretKeyHex);
std::string dilithiumSign(const std::vector<uint8_t>& message, const std::vector<uint8_t>& secretKey);

// Verify a Dilithium signature
bool dilithiumVerify(const std::string& message, const std::string& signatureHex,
                     const std::string& publicKeyHex);
bool dilithiumVerify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature,
                     const std::vector<uint8_t>& publicKey);

// ============================================================================
// CRYSTALS-Kyber — Key Encapsulation Mechanism
// ============================================================================

// Generate a Kyber key pair
KyberKeyPair generateKyberKeyPair();

// Encapsulate: generate shared secret + ciphertext from public key
KyberEncapsulation kyberEncapsulate(const std::string& publicKeyHex);
KyberEncapsulation kyberEncapsulate(const std::vector<uint8_t>& publicKey);

// Decapsulate: recover shared secret from ciphertext + secret key
std::vector<uint8_t> kyberDecapsulate(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& secretKey);
std::string kyberDecapsulateHex(const std::string& ciphertextHex, const std::string& secretKeyHex);

// ============================================================================
// Quantum-safe hash functions
// ============================================================================

// SHA3-256 (quantum-resistant hash, 128-bit post-quantum security)
std::string sha3_256(const std::string& data);
std::string sha3_256(const std::vector<uint8_t>& data);

// SHAKE-256 with variable output length (used in Dilithium internally)
std::vector<uint8_t> shake256(const std::vector<uint8_t>& data, size_t outputLen);

// ============================================================================
// Quantum-safe address generation
// ============================================================================

// Generate a quantum-resistant address from a Dilithium public key
// Uses SHA3-256 hash of the public key, prefixed with "qGXC" (quantum GXC)
std::string generateQuantumAddress(const std::string& dilithiumPublicKeyHex, bool testnet = false);

// ============================================================================
// Utility functions
// ============================================================================

// Hex encoding/decoding (reuses Crypto utilities internally)
std::vector<uint8_t> hexToBytes(const std::string& hex);
std::string bytesToHex(const std::vector<uint8_t>& bytes);
std::string bytesToHex(const uint8_t* data, size_t len);

// Cryptographically secure random bytes
std::vector<uint8_t> secureRandomBytes(size_t count);

// Validate that a key is the correct size for its type
bool isValidDilithiumPublicKey(const std::string& publicKeyHex);
bool isValidDilithiumSecretKey(const std::string& secretKeyHex);
bool isValidKyberPublicKey(const std::string& publicKeyHex);

} // namespace QuantumCrypto
