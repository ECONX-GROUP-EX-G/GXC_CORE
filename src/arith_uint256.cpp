#include "../include/arith_uint256.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace {

/** Hex digit -> value, or -1 when the character is not a hex digit. */
inline int HexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

arith_uint256::arith_uint256() {
    memset(pn, 0, sizeof(pn));
}

arith_uint256::arith_uint256(uint64_t b) {
    memset(pn, 0, sizeof(pn));
    pn[0] = static_cast<uint32_t>(b);
    pn[1] = static_cast<uint32_t>(b >> 32);
}

arith_uint256::arith_uint256(const std::string& str) {
    SetHex(str);
}

// --- comparison ------------------------------------------------------------

bool arith_uint256::operator==(const arith_uint256& b) const {
    return memcmp(pn, b.pn, sizeof(pn)) == 0;
}

bool arith_uint256::operator!=(const arith_uint256& b) const {
    return !(*this == b);
}

bool arith_uint256::operator<(const arith_uint256& b) const {
    for (int i = WIDTH - 1; i >= 0; i--) {
        if (pn[i] < b.pn[i]) return true;
        if (pn[i] > b.pn[i]) return false;
    }
    return false;
}

bool arith_uint256::operator<=(const arith_uint256& b) const {
    return !(b < *this);
}

bool arith_uint256::operator>(const arith_uint256& b) const {
    return b < *this;
}

bool arith_uint256::operator>=(const arith_uint256& b) const {
    return !(*this < b);
}

// --- arithmetic ------------------------------------------------------------

arith_uint256 arith_uint256::operator~() const {
    arith_uint256 result;
    for (int i = 0; i < WIDTH; i++)
        result.pn[i] = ~pn[i];
    return result;
}

arith_uint256 arith_uint256::operator-() const {
    arith_uint256 result = ~(*this);
    ++result;
    return result;
}

arith_uint256 arith_uint256::operator+(const arith_uint256& b) const {
    arith_uint256 result;
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; i++) {
        uint64_t sum = static_cast<uint64_t>(pn[i]) + b.pn[i] + carry;
        result.pn[i] = static_cast<uint32_t>(sum);
        carry = sum >> 32;
    }
    return result;
}

arith_uint256 arith_uint256::operator-(const arith_uint256& b) const {
    // a - b == a + (-b), modulo 2^256.
    return *this + (-b);
}

arith_uint256 arith_uint256::operator*(const arith_uint256& b) const {
    // Schoolbook multiplication truncated to 256 bits.
    arith_uint256 result;
    for (int j = 0; j < WIDTH; j++) {
        uint64_t carry = 0;
        for (int i = 0; i + j < WIDTH; i++) {
            uint64_t n = carry + result.pn[i + j] +
                         static_cast<uint64_t>(pn[j]) * b.pn[i];
            result.pn[i + j] = static_cast<uint32_t>(n);
            carry = n >> 32;
        }
    }
    return result;
}

arith_uint256 arith_uint256::operator/(const arith_uint256& b) const {
    if (b.IsZero())
        throw std::domain_error("arith_uint256: division by zero");

    // Restoring shift-subtract long division, most significant bit first.
    arith_uint256 div = b;       // shifted divisor
    arith_uint256 num = *this;   // running remainder
    arith_uint256 result;

    int num_bits = num.bits();
    int div_bits = div.bits();
    if (div_bits > num_bits)
        return result;           // divisor larger than dividend -> quotient 0

    int shift = num_bits - div_bits;
    div <<= shift;               // align divisor with the dividend
    while (shift >= 0) {
        if (num >= div) {
            num -= div;
            result.pn[shift / 32] |= (1U << (shift & 31));
        }
        div >>= 1;
        shift--;
    }
    return result;
}

arith_uint256 arith_uint256::operator<<(unsigned int shift) const {
    arith_uint256 result;
    if (shift >= 256) return result;

    const unsigned int limbShift = shift / 32;
    const unsigned int bitShift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (bitShift != 0 && i + static_cast<int>(limbShift) + 1 < WIDTH)
            result.pn[i + limbShift + 1] |= (pn[i] >> (32 - bitShift));
        if (i + static_cast<int>(limbShift) < WIDTH)
            result.pn[i + limbShift] |= (pn[i] << bitShift);
    }
    return result;
}

arith_uint256 arith_uint256::operator>>(unsigned int shift) const {
    arith_uint256 result;
    if (shift >= 256) return result;

    const unsigned int limbShift = shift / 32;
    const unsigned int bitShift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (bitShift != 0 && i - static_cast<int>(limbShift) - 1 >= 0)
            result.pn[i - limbShift - 1] |= (pn[i] << (32 - bitShift));
        if (i - static_cast<int>(limbShift) >= 0)
            result.pn[i - limbShift] |= (pn[i] >> bitShift);
    }
    return result;
}

arith_uint256& arith_uint256::operator+=(const arith_uint256& b) { *this = *this + b; return *this; }
arith_uint256& arith_uint256::operator-=(const arith_uint256& b) { *this = *this - b; return *this; }
arith_uint256& arith_uint256::operator*=(const arith_uint256& b) { *this = *this * b; return *this; }
arith_uint256& arith_uint256::operator/=(const arith_uint256& b) { *this = *this / b; return *this; }
arith_uint256& arith_uint256::operator<<=(unsigned int shift) { *this = *this << shift; return *this; }
arith_uint256& arith_uint256::operator>>=(unsigned int shift) { *this = *this >> shift; return *this; }

arith_uint256& arith_uint256::operator++() {
    int i = 0;
    while (i < WIDTH && ++pn[i] == 0)
        i++;
    return *this;
}

arith_uint256& arith_uint256::operator--() {
    int i = 0;
    while (i < WIDTH && --pn[i] == 0xffffffffU)
        i++;
    return *this;
}

// --- conversion ------------------------------------------------------------

std::string arith_uint256::GetHex() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = WIDTH - 1; i >= 0; i--)
        ss << std::setw(8) << pn[i];
    return ss.str();
}

void arith_uint256::SetHex(const std::string& str) {
    memset(pn, 0, sizeof(pn));

    size_t begin = 0;
    while (begin < str.size() && std::isspace(static_cast<unsigned char>(str[begin])))
        begin++;
    if (begin + 1 < str.size() && str[begin] == '0' &&
        (str[begin + 1] == 'x' || str[begin + 1] == 'X'))
        begin += 2;

    // Consume hex digits from the right (least significant) end. Non-hex
    // characters terminate the scan; digits beyond 256 bits are discarded.
    int nibble = 0;
    for (size_t i = str.size(); i-- > begin && nibble < 64;) {
        const int digit = HexDigit(str[i]);
        if (digit < 0) break;
        pn[nibble / 8] |= static_cast<uint32_t>(digit) << (4 * (nibble % 8));
        nibble++;
    }
}

double arith_uint256::getdouble() const {
    double ret = 0.0;
    double fact = 1.0;
    for (int i = 0; i < WIDTH; i++) {
        ret += fact * pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}

arith_uint256& arith_uint256::SetCompact(uint32_t nCompact, bool* pfNegative, bool* pfOverflow) {
    const int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;

    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        *this = arith_uint256(static_cast<uint64_t>(nWord));
    } else {
        *this = arith_uint256(static_cast<uint64_t>(nWord));
        *this <<= 8 * (nSize - 3);
    }

    if (pfNegative)
        *pfNegative = nWord != 0 && (nCompact & 0x00800000) != 0;
    if (pfOverflow)
        *pfOverflow = nWord != 0 && ((nSize > 34) ||
                                     (nWord > 0xff && nSize > 33) ||
                                     (nWord > 0xffff && nSize > 32));
    return *this;
}

uint32_t arith_uint256::GetCompact(bool fNegative) const {
    int nSize = (bits() + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = static_cast<uint32_t>(GetLow64() << (8 * (3 - nSize)));
    } else {
        arith_uint256 bn = *this >> (8 * (nSize - 3));
        nCompact = static_cast<uint32_t>(bn.GetLow64());
    }
    // The 0x00800000 bit denotes the sign, so a mantissa that would set it has
    // to be shifted down one byte and the exponent bumped instead.
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    nCompact |= static_cast<uint32_t>(nSize) << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff)) ? 0x00800000 : 0;
    return nCompact;
}

uint64_t arith_uint256::GetLow64() const {
    return pn[0] | (static_cast<uint64_t>(pn[1]) << 32);
}

bool arith_uint256::IsZero() const {
    for (int i = 0; i < WIDTH; i++) {
        if (pn[i] != 0) return false;
    }
    return true;
}

int arith_uint256::bits() const {
    for (int pos = WIDTH - 1; pos >= 0; pos--) {
        if (pn[pos]) {
            for (int nbits = 31; nbits > 0; nbits--) {
                if (pn[pos] & (1U << nbits))
                    return 32 * pos + nbits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

// --- proof-of-work helpers -------------------------------------------------

arith_uint256 GetBlockProof(uint32_t nBits) {
    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow || target.IsZero())
        return arith_uint256(0);

    // Expected hashes to find a block = 2^256 / (target + 1). 2^256 does not
    // fit in 256 bits, so use the identity
    //     2^256 / (target + 1) == ~target / (target + 1) + 1
    // which stays inside the type for every non-zero target.
    arith_uint256 divisor = target;
    ++divisor;
    return (~target) / divisor + arith_uint256(1);
}

// Mainnet uses Bitcoin's classic difficulty-1 target (0x1d00ffff), so a
// difficulty of D denotes the same amount of expected work it does on Bitcoin.
// Testnet uses a near-maximal target so that a single CPU finds blocks
// immediately, which is what makes the network usable for development.
static constexpr uint32_t MAINNET_POW_LIMIT_BITS = 0x1d00ffffU;
static constexpr uint32_t TESTNET_POW_LIMIT_BITS = 0x207fffffU;

uint32_t PowLimitBits(bool testnet) {
    return testnet ? TESTNET_POW_LIMIT_BITS : MAINNET_POW_LIMIT_BITS;
}

arith_uint256 PowLimit(bool testnet) {
    arith_uint256 limit;
    limit.SetCompact(PowLimitBits(testnet));
    return limit;
}

arith_uint256 DifficultyToTarget(double difficulty, bool testnet) {
    const arith_uint256 limit = PowLimit(testnet);
    if (!(difficulty > 0.0) || std::isnan(difficulty))
        return limit;   // difficulty <= 0 is meaningless; treat as "easiest"

    if (difficulty == 1.0)
        return limit;

    // Integer division truncates, so the numerator is scaled up first to keep
    // fractional difficulties meaningful. How far it can be scaled depends on
    // the headroom above the limit's most significant bit -- the testnet limit
    // is a 255-bit value, so shifting it a fixed 32 places would overflow and
    // silently produce a target that no hash could ever meet.
    const int headroom = 256 - limit.bits();
    const int shift = std::min(32, std::max(0, headroom));

    const double scaleFactor = static_cast<double>(uint64_t(1) << shift);
    const double scaledDivisor = difficulty * scaleFactor;

    // Beyond 2^63 the divisor no longer fits a uint64_t; such a difficulty is
    // far past anything reachable, so pin the target at its minimum.
    if (scaledDivisor >= 9223372036854775808.0)
        return arith_uint256(1);

    const uint64_t divisor = static_cast<uint64_t>(scaledDivisor);
    if (divisor == 0)
        return limit;

    arith_uint256 target = (limit << shift) / arith_uint256(divisor);
    if (target.IsZero())
        target = arith_uint256(1);
    if (target > limit)
        target = limit;
    return target;
}

double TargetToDifficulty(const arith_uint256& target, bool testnet) {
    if (target.IsZero())
        return 0.0;
    return PowLimit(testnet).getdouble() / target.getdouble();
}

arith_uint256 GetBlockProof(double difficulty, bool testnet) {
    return GetBlockProof(DifficultyToTarget(difficulty, testnet).GetCompact());
}
