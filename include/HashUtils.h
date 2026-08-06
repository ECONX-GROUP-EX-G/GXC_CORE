#pragma once

#include <string>
#include <vector>
#include <cstdint>

// SHA-256 hash function
std::string sha256(const std::string& data);

// Double SHA-256 hash function (used in Bitcoin)
std::string sha256d(const std::string& data);

// Ethash function (simplified for demonstration)
std::string ethash(const std::string& data, uint64_t nonce);


// GXHash function (ASIC-resistant, memory-hard)
std::string gxhash(const std::string& data, uint64_t nonce);

// RIPEMD-160 hash function
std::string ripemd160(const std::string& data);

// Keccak-256 hash function
std::string keccak256(const std::string& data);

// Calculate Merkle root from a list of transaction hashes
std::string calculateMerkleRoot(const std::vector<std::string>& txHashes);

/**
 * Check a proof-of-work hash against the target implied by `difficulty`.
 *
 * The hash is interpreted as a big-endian 256-bit integer and must be less than
 * or equal to `PowLimit(testnet) / difficulty`. This is the single definition
 * of "meets the target" used by both the miner and the validator; they must not
 * diverge or the chain cannot advance.
 *
 * A malformed hash (not 64 hex characters) never meets the target.
 */
bool meetsTarget(const std::string& hash, double difficulty, bool testnet);

/** Convenience overload using the network selected in the node Config. */
bool meetsTarget(const std::string& hash, double difficulty);

// Convert a hash string to a numeric value for comparison
double hashToValue(const std::string& hash);

/** True when `hash` is exactly 64 hexadecimal characters. */
bool isValidHash256(const std::string& hash);
