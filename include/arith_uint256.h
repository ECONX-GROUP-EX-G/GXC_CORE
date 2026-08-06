#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * 256-bit unsigned integer used for proof-of-work targets and cumulative
 * chainwork.
 *
 * Semantics follow Bitcoin Core's `base_uint<256>`: the value is stored as
 * eight little-endian 32-bit limbs (`pn[0]` is least significant), while the
 * hex representation produced by GetHex()/consumed by SetHex() is big-endian,
 * matching the way block hashes are displayed.
 *
 * All arithmetic is modulo 2^256; there is no overflow trap. Division by zero
 * throws std::domain_error.
 */
class arith_uint256 {
private:
    static constexpr int WIDTH = 256 / 32;
    uint32_t pn[WIDTH];

public:
    arith_uint256();
    explicit arith_uint256(uint64_t b);
    explicit arith_uint256(const std::string& str);

    // Comparison operators
    bool operator==(const arith_uint256& b) const;
    bool operator!=(const arith_uint256& b) const;
    bool operator<(const arith_uint256& b) const;
    bool operator<=(const arith_uint256& b) const;
    bool operator>(const arith_uint256& b) const;
    bool operator>=(const arith_uint256& b) const;

    // Arithmetic operators
    arith_uint256 operator+(const arith_uint256& b) const;
    arith_uint256 operator-(const arith_uint256& b) const;
    arith_uint256 operator*(const arith_uint256& b) const;
    arith_uint256 operator/(const arith_uint256& b) const;
    arith_uint256 operator~() const;
    arith_uint256 operator-() const;             // two's complement negation
    arith_uint256 operator<<(unsigned int shift) const;
    arith_uint256 operator>>(unsigned int shift) const;

    arith_uint256& operator+=(const arith_uint256& b);
    arith_uint256& operator-=(const arith_uint256& b);
    arith_uint256& operator*=(const arith_uint256& b);
    arith_uint256& operator/=(const arith_uint256& b);
    arith_uint256& operator<<=(unsigned int shift);
    arith_uint256& operator>>=(unsigned int shift);
    arith_uint256& operator++();                 // pre-increment
    arith_uint256& operator--();                 // pre-decrement

    // Conversion
    std::string GetHex() const;                  // 64 lowercase hex chars, big-endian
    void SetHex(const std::string& str);         // tolerant of "0x", short and over-long input
    double getdouble() const;

    /**
     * Decode a Bitcoin-style compact ("nBits") target.
     *
     * The encoding is a base-256 scientific notation: the high byte is the
     * exponent (byte length of the value) and the low three bytes are the
     * mantissa. Bit 0x00800000 of the mantissa is the sign bit.
     *
     * @param pfNegative set to true when the encoded value is negative
     * @param pfOverflow set to true when the encoded value exceeds 256 bits
     */
    arith_uint256& SetCompact(uint32_t nCompact, bool* pfNegative = nullptr, bool* pfOverflow = nullptr);
    uint32_t GetCompact(bool fNegative = false) const;

    uint64_t GetLow64() const;

    // Utility
    bool IsZero() const;
    int bits() const;                            // position of the highest set bit (0 when zero)
};

/**
 * Work contributed by a block whose target is `nBits`, i.e. the expected number
 * of hashes needed to find it: 2^256 / (target + 1).
 */
arith_uint256 GetBlockProof(uint32_t nBits);

/** Largest permitted target ("pow limit") for the given network. */
arith_uint256 PowLimit(bool testnet);

/** Compact encoding of PowLimit(testnet). */
uint32_t PowLimitBits(bool testnet);

/**
 * Convert a human-readable difficulty into the 256-bit target it denotes:
 * target = PowLimit / difficulty. Difficulties <= 0 are clamped to the limit.
 */
arith_uint256 DifficultyToTarget(double difficulty, bool testnet);

/** Inverse of DifficultyToTarget: difficulty = PowLimit / target. */
double TargetToDifficulty(const arith_uint256& target, bool testnet);

/** Work contributed by a block mined at `difficulty` on the given network. */
arith_uint256 GetBlockProof(double difficulty, bool testnet);
