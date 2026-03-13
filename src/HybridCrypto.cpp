#include "../include/HybridCrypto.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace HybridCrypto {

// ============================================================================
// HybridSignature serialization
// ============================================================================

std::string HybridSignature::serialize() const {
    // Format: <type_byte_hex> <classical_sig_len_hex(4)> <classical_sig> <quantum_sig>
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    // Type byte
    ss << std::setw(2) << static_cast<int>(static_cast<uint8_t>(type));

    // Classical signature with length prefix
    uint16_t classicalLen = static_cast<uint16_t>(classicalSignature.length() / 2);
    ss << std::setw(4) << classicalLen;
    ss << classicalSignature;

    // Quantum signature (remainder)
    ss << quantumSignature;

    return ss.str();
}

HybridSignature HybridSignature::deserialize(const std::string& serialized) {
    HybridSignature sig;

    if (serialized.length() < 6) {
        // Too short, treat as classical
        sig.type = SignatureType::CLASSICAL;
        sig.classicalSignature = serialized;
        sig.quantumSignature = "";
        return sig;
    }

    // Parse type byte
    uint8_t typeByte = static_cast<uint8_t>(strtol(serialized.substr(0, 2).c_str(), nullptr, 16));

    if (typeByte == SIG_TYPE_HYBRID) {
        sig.type = SignatureType::HYBRID;

        // Parse classical signature length
        uint16_t classicalLen = static_cast<uint16_t>(strtol(serialized.substr(2, 4).c_str(), nullptr, 16));
        size_t classicalHexLen = static_cast<size_t>(classicalLen) * 2;

        if (6 + classicalHexLen > serialized.length()) {
            throw std::runtime_error("HybridCrypto: Invalid hybrid signature format");
        }

        sig.classicalSignature = serialized.substr(6, classicalHexLen);
        sig.quantumSignature = serialized.substr(6 + classicalHexLen);
    } else if (typeByte == SIG_TYPE_QUANTUM) {
        sig.type = SignatureType::QUANTUM;
        sig.classicalSignature = "";
        // Skip type(2) + length(4) prefix
        sig.quantumSignature = serialized.substr(6);
    } else if (typeByte == SIG_TYPE_CLASSICAL) {
        sig.type = SignatureType::CLASSICAL;
        sig.classicalSignature = serialized.substr(6);
        sig.quantumSignature = "";
    } else {
        // Unknown type byte — assume legacy classical signature (no prefix)
        sig.type = SignatureType::CLASSICAL;
        sig.classicalSignature = serialized;
        sig.quantumSignature = "";
    }

    return sig;
}

// ============================================================================
// Key generation
// ============================================================================

HybridKeyPair generateHybridKeyPair() {
    HybridKeyPair kp;

    // Generate classical secp256k1 key pair
    Crypto::KeyPair classicalKP = Crypto::generateKeyPair();
    kp.classicalPrivateKey = classicalKP.privateKey;
    kp.classicalPublicKey = classicalKP.publicKey;

    // Generate quantum-resistant Dilithium key pair
    QuantumCrypto::DilithiumKeyPair quantumKP = QuantumCrypto::generateDilithiumKeyPair();
    kp.quantumPrivateKey = quantumKP.secretKeyHex;
    kp.quantumPublicKey = quantumKP.publicKeyHex;

    // Compute combined fingerprint
    kp.combinedFingerprint = computeCombinedFingerprint(kp.classicalPublicKey, kp.quantumPublicKey);

    return kp;
}

std::string deriveClassicalPublicKey(const std::string& classicalPrivateKeyHex) {
    return Crypto::derivePublicKey(classicalPrivateKeyHex);
}

std::string deriveQuantumPublicKey(const std::string& /* quantumPrivateKeyHex */) {
    // Dilithium doesn't support public key derivation from private key alone
    // in the same way ECDSA does. The public key is generated alongside the
    // private key and must be stored. Return empty to signal this.
    return "";
}

// ============================================================================
// Signing
// ============================================================================

HybridSignature hybridSign(const std::string& data, const HybridKeyPair& keyPair) {
    return hybridSign(data, keyPair.classicalPrivateKey, keyPair.quantumPrivateKey);
}

HybridSignature hybridSign(const std::string& data,
                           const std::string& classicalPrivateKeyHex,
                           const std::string& quantumPrivateKeyHex) {
    HybridSignature sig;
    sig.type = SignatureType::HYBRID;

    // Sign with classical ECDSA
    sig.classicalSignature = Crypto::signData(data, classicalPrivateKeyHex);

    // Sign with quantum-resistant Dilithium
    sig.quantumSignature = QuantumCrypto::dilithiumSign(data, quantumPrivateKeyHex);

    return sig;
}

HybridSignature classicalSign(const std::string& data, const std::string& classicalPrivateKeyHex) {
    HybridSignature sig;
    sig.type = SignatureType::CLASSICAL;
    sig.classicalSignature = Crypto::signData(data, classicalPrivateKeyHex);
    sig.quantumSignature = "";
    return sig;
}

HybridSignature quantumSign(const std::string& data, const std::string& quantumPrivateKeyHex) {
    HybridSignature sig;
    sig.type = SignatureType::QUANTUM;
    sig.classicalSignature = "";
    sig.quantumSignature = QuantumCrypto::dilithiumSign(data, quantumPrivateKeyHex);
    return sig;
}

// ============================================================================
// Verification
// ============================================================================

bool hybridVerify(const std::string& data, const HybridSignature& signature,
                  const std::string& classicalPublicKeyHex,
                  const std::string& quantumPublicKeyHex) {
    switch (signature.type) {
        case SignatureType::HYBRID: {
            // BOTH must verify for a hybrid signature
            bool classicalOk = Crypto::verifySignature(data, signature.classicalSignature,
                                                        classicalPublicKeyHex);
            if (!classicalOk) return false;

            bool quantumOk = QuantumCrypto::dilithiumVerify(data, signature.quantumSignature,
                                                             quantumPublicKeyHex);
            return quantumOk;
        }

        case SignatureType::CLASSICAL: {
            // Legacy mode: only classical verification
            return Crypto::verifySignature(data, signature.classicalSignature,
                                           classicalPublicKeyHex);
        }

        case SignatureType::QUANTUM: {
            // Quantum-only mode
            return QuantumCrypto::dilithiumVerify(data, signature.quantumSignature,
                                                   quantumPublicKeyHex);
        }

        default:
            return false;
    }
}

bool verify(const std::string& data, const std::string& serializedSignature,
            const std::string& classicalPublicKeyHex,
            const std::string& quantumPublicKeyHex) {
    try {
        HybridSignature sig = HybridSignature::deserialize(serializedSignature);
        return hybridVerify(data, sig, classicalPublicKeyHex, quantumPublicKeyHex);
    } catch (...) {
        // If deserialization fails, try as a raw classical signature
        return Crypto::verifySignature(data, serializedSignature, classicalPublicKeyHex);
    }
}

bool verifyClassical(const std::string& data, const std::string& signatureHex,
                     const std::string& classicalPublicKeyHex) {
    return Crypto::verifySignature(data, signatureHex, classicalPublicKeyHex);
}

bool verifyQuantum(const std::string& data, const std::string& signatureHex,
                   const std::string& quantumPublicKeyHex) {
    return QuantumCrypto::dilithiumVerify(data, signatureHex, quantumPublicKeyHex);
}

// ============================================================================
// Address generation
// ============================================================================

std::string generateHybridAddress(const std::string& classicalPublicKeyHex,
                                  const std::string& quantumPublicKeyHex,
                                  bool testnet) {
    // Combine both public keys and hash with SHA3-256
    std::string combined = classicalPublicKeyHex + quantumPublicKeyHex;
    std::string hash = QuantumCrypto::sha3_256(combined);

    // Use first 40 hex chars (20 bytes) for the address
    std::string addressHash = hash.substr(0, 40);

    // Hybrid address prefix
    std::string prefix = testnet ? "htGXC" : "hGXC";
    return prefix + addressHash;
}

std::string generateHybridAddress(const HybridKeyPair& keyPair, bool testnet) {
    return generateHybridAddress(keyPair.classicalPublicKey, keyPair.quantumPublicKey, testnet);
}

// ============================================================================
// Address validation
// ============================================================================

bool isHybridAddress(const std::string& address) {
    if (address.length() < 44) return false;
    return address.substr(0, 4) == "hGXC" || address.substr(0, 5) == "htGXC";
}

bool isQuantumAddress(const std::string& address) {
    if (address.length() < 44) return false;
    return address.substr(0, 4) == "qGXC" || address.substr(0, 5) == "qtGXC";
}

bool isClassicalAddress(const std::string& address) {
    if (address.length() < 30) return false;
    // Classical addresses start with GXC or tGXC but NOT hGXC, qGXC, htGXC, qtGXC
    if (address.substr(0, 4) == "hGXC" || address.substr(0, 4) == "qGXC") return false;
    if (address.substr(0, 5) == "htGXC" || address.substr(0, 5) == "qtGXC") return false;
    return address.substr(0, 3) == "GXC" || address.substr(0, 4) == "tGXC";
}

bool isValidGXCAddress(const std::string& address) {
    return isClassicalAddress(address) || isHybridAddress(address) || isQuantumAddress(address);
}

// ============================================================================
// Signature type detection
// ============================================================================

SignatureType detectSignatureType(const std::string& serializedSignature) {
    if (serializedSignature.length() < 2) {
        return SignatureType::CLASSICAL;
    }

    uint8_t typeByte = static_cast<uint8_t>(strtol(serializedSignature.substr(0, 2).c_str(), nullptr, 16));

    switch (typeByte) {
        case SIG_TYPE_HYBRID:    return SignatureType::HYBRID;
        case SIG_TYPE_QUANTUM:   return SignatureType::QUANTUM;
        case SIG_TYPE_CLASSICAL: return SignatureType::CLASSICAL;
        default:
            // No recognized prefix → legacy classical signature
            return SignatureType::CLASSICAL;
    }
}

// ============================================================================
// Key serialization
// ============================================================================

std::string serializeKeyPair(const HybridKeyPair& keyPair) {
    // Format: HYBRID_KP_V1|classical_priv|classical_pub|quantum_priv|quantum_pub|fingerprint
    return "HYBRID_KP_V1|" +
           keyPair.classicalPrivateKey + "|" +
           keyPair.classicalPublicKey + "|" +
           keyPair.quantumPrivateKey + "|" +
           keyPair.quantumPublicKey + "|" +
           keyPair.combinedFingerprint;
}

HybridKeyPair deserializeKeyPair(const std::string& serialized) {
    HybridKeyPair kp;

    // Split by '|'
    std::vector<std::string> parts;
    std::string current;
    for (char c : serialized) {
        if (c == '|') {
            parts.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        parts.push_back(current);
    }

    if (parts.size() < 6 || parts[0] != "HYBRID_KP_V1") {
        throw std::runtime_error("HybridCrypto: Invalid key pair format");
    }

    kp.classicalPrivateKey = parts[1];
    kp.classicalPublicKey = parts[2];
    kp.quantumPrivateKey = parts[3];
    kp.quantumPublicKey = parts[4];
    kp.combinedFingerprint = parts[5];

    return kp;
}

// ============================================================================
// Migration utilities
// ============================================================================

HybridKeyPair upgradeClassicalKey(const std::string& existingClassicalPrivateKeyHex) {
    HybridKeyPair kp;

    // Keep the existing classical key
    kp.classicalPrivateKey = existingClassicalPrivateKeyHex;
    kp.classicalPublicKey = Crypto::derivePublicKey(existingClassicalPrivateKeyHex);

    // Generate a new quantum-resistant key pair
    QuantumCrypto::DilithiumKeyPair quantumKP = QuantumCrypto::generateDilithiumKeyPair();
    kp.quantumPrivateKey = quantumKP.secretKeyHex;
    kp.quantumPublicKey = quantumKP.publicKeyHex;

    // Compute combined fingerprint
    kp.combinedFingerprint = computeCombinedFingerprint(kp.classicalPublicKey, kp.quantumPublicKey);

    return kp;
}

std::string computeCombinedFingerprint(const std::string& classicalPublicKeyHex,
                                       const std::string& quantumPublicKeyHex) {
    std::string combined = classicalPublicKeyHex + quantumPublicKeyHex;
    return QuantumCrypto::sha3_256(combined);
}

} // namespace HybridCrypto
