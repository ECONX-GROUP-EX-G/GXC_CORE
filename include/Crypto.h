#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

namespace Crypto {

// Key pair structure
struct KeyPair {
    std::string privateKey;  // Hex-encoded private key (32 bytes)
    std::string publicKey;   // Hex-encoded compressed public key (33 bytes)
};

// Generate a new secp256k1 key pair
KeyPair generateKeyPair();

// Derive public key from private key using secp256k1
std::string derivePublicKey(const std::string& privateKeyHex);

// Sign data using ECDSA with secp256k1
std::string signData(const std::string& data, const std::string& privateKeyHex);

// Verify ECDSA signature
bool verifySignature(const std::string& data, const std::string& signature, const std::string& publicKeyHex);

// Hash functions
std::string sha256(const std::string& data);
std::string sha256d(const std::string& data); // Double SHA-256
std::string ripemd160(const std::string& data);
std::string keccak256(const std::string& data); // Proper Keccak-256

// --- Addresses --------------------------------------------------------------
//
// Format:  <prefix> || hex(hash160) || hex(checksum)
//   prefix    "GXC" on mainnet, "tGXC" on testnet
//   hash160   RIPEMD-160(SHA-256(pubkey)), all 20 bytes -- 40 hex characters
//   checksum  first 4 bytes of SHA-256d(prefix || hash160) -- 8 hex characters
//
// The checksum matches Base58Check's strength: a corrupted address is accepted
// with probability 2^-32. Without one, a mistyped address is indistinguishable
// from a valid one and the funds sent to it are unrecoverable.
//
// The hash is carried at its full 160 bits. Truncating it to 136 (as an earlier
// version did) left 2^68 collision resistance -- roughly four thousand times
// weaker than Bitcoin, and low enough to be worth attacking classically, before
// any quantum consideration enters into it.
//
// A Bech32 encoding would give stronger guarantees still (all errors up to four
// characters detected, rather than probabilistic) at the cost of changing how
// addresses look. That remains open; see docs/ARCHITECTURE.md.

/** Derive the address for a compressed secp256k1 public key. */
std::string generateAddress(const std::string& publicKeyHex, bool testnet = false);

/** True when `address` is well-formed and its checksum verifies. */
bool isValidAddress(const std::string& address);

/** True when `address` is a well-formed testnet address. */
bool isTestnetAddress(const std::string& address);

/**
 * The 20-byte hash160 an address commits to, hex-encoded.
 * Returns an empty string when the address is malformed.
 */
std::string addressHash160(const std::string& address);

// Utility functions
std::vector<uint8_t> hexToBytes(const std::string& hex);
std::string bytesToHex(const std::vector<uint8_t>& bytes);
std::string bytesToHex(const uint8_t* data, size_t len);

} // namespace Crypto
