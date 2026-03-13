#include "../include/QuantumCrypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

namespace QuantumCrypto {

// ============================================================================
// Utility functions
// ============================================================================

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<uint8_t> secureRandomBytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("QuantumCrypto: CSPRNG failure");
    }
    return bytes;
}

// ============================================================================
// SHA3-256 and SHAKE-256 implementations (via OpenSSL EVP)
// ============================================================================

std::string sha3_256(const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("QuantumCrypto: Failed to create EVP context");
    }

    const EVP_MD* md = EVP_sha3_256();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHA3-256 not available");
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.c_str(), data.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHA3-256 digest failed");
    }

    uint8_t hash[32];
    unsigned int hashLen;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHA3-256 finalize failed");
    }

    EVP_MD_CTX_free(ctx);
    return bytesToHex(hash, hashLen);
}

std::string sha3_256(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("QuantumCrypto: Failed to create EVP context");
    }

    const EVP_MD* md = EVP_sha3_256();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHA3-256 not available");
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHA3-256 digest failed");
    }

    uint8_t hash[32];
    unsigned int hashLen;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHA3-256 finalize failed");
    }

    EVP_MD_CTX_free(ctx);
    return bytesToHex(hash, hashLen);
}

std::vector<uint8_t> shake256(const std::vector<uint8_t>& data, size_t outputLen) {
    std::vector<uint8_t> output(outputLen);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("QuantumCrypto: Failed to create EVP context for SHAKE256");
    }

    const EVP_MD* md = EVP_shake256();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHAKE256 not available");
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinalXOF(ctx, output.data(), outputLen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("QuantumCrypto: SHAKE256 operation failed");
    }

    EVP_MD_CTX_free(ctx);
    return output;
}

// ============================================================================
// Internal helper: Deterministic expansion via SHAKE-256
// Used to expand seeds into polynomial coefficients for Dilithium/Kyber
// ============================================================================

static std::vector<uint8_t> expandSeed(const std::vector<uint8_t>& seed,
                                        const std::vector<uint8_t>& nonce,
                                        size_t outputLen) {
    std::vector<uint8_t> input;
    input.insert(input.end(), seed.begin(), seed.end());
    input.insert(input.end(), nonce.begin(), nonce.end());
    return shake256(input, outputLen);
}

// ============================================================================
// Modular arithmetic helpers for lattice operations
// ============================================================================

static int32_t modQ(int64_t a, int32_t q) {
    int64_t r = a % q;
    if (r < 0) r += q;
    return static_cast<int32_t>(r);
}

// Barrett reduction for Dilithium modulus
static int32_t barrettReduceDilithium(int64_t a) {
    return modQ(a, DILITHIUM_Q);
}

// Barrett reduction for Kyber modulus
static int32_t barrettReduceKyber(int64_t a) {
    return modQ(a, KYBER_Q);
}

// ============================================================================
// Polynomial operations for lattice-based crypto
// ============================================================================

using Poly = std::vector<int32_t>;

static Poly polyNew(int n) {
    return Poly(n, 0);
}

static Poly polyAdd(const Poly& a, const Poly& b, int32_t q) {
    size_t n = a.size();
    Poly c(n);
    for (size_t i = 0; i < n; i++) {
        c[i] = modQ(static_cast<int64_t>(a[i]) + b[i], q);
    }
    return c;
}

static Poly polySub(const Poly& a, const Poly& b, int32_t q) {
    size_t n = a.size();
    Poly c(n);
    for (size_t i = 0; i < n; i++) {
        c[i] = modQ(static_cast<int64_t>(a[i]) - b[i], q);
    }
    return c;
}

// Schoolbook polynomial multiplication mod (X^n + 1, q)
static Poly polyMul(const Poly& a, const Poly& b, int n, int32_t q) {
    Poly c(n, 0);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int64_t prod = static_cast<int64_t>(a[i]) * b[j];
            int idx = i + j;
            if (idx >= n) {
                // Reduction mod X^n + 1: X^(n+k) = -X^k
                c[idx - n] = modQ(static_cast<int64_t>(c[idx - n]) - prod, q);
            } else {
                c[idx] = modQ(static_cast<int64_t>(c[idx]) + prod, q);
            }
        }
    }
    return c;
}

// Sample a polynomial with coefficients uniformly in [0, q)
static Poly sampleUniform(const std::vector<uint8_t>& seed, uint8_t nonce1, uint8_t nonce2,
                           int n, int32_t q) {
    std::vector<uint8_t> nonceVec = {nonce1, nonce2};
    // Need 3 bytes per coefficient attempt (rejection sampling)
    std::vector<uint8_t> expanded = expandSeed(seed, nonceVec, static_cast<size_t>(n) * 4);
    Poly p(n);
    size_t j = 0;
    for (int i = 0; i < n && j + 2 < expanded.size(); ) {
        // Take 3 bytes, extract a value < q
        uint32_t val = (static_cast<uint32_t>(expanded[j]) |
                       (static_cast<uint32_t>(expanded[j + 1]) << 8) |
                       (static_cast<uint32_t>(expanded[j + 2] & 0x7F) << 16));
        j += 3;
        if (static_cast<int32_t>(val) < q) {
            p[i] = static_cast<int32_t>(val);
            i++;
        }
        // If we run out, generate more
        if (j + 2 >= expanded.size() && i < n) {
            nonceVec.push_back(static_cast<uint8_t>(j & 0xFF));
            expanded = expandSeed(seed, nonceVec, static_cast<size_t>(n) * 4);
            j = 0;
        }
    }
    return p;
}

// Sample a polynomial with small coefficients (CBD - Centered Binomial Distribution)
static Poly sampleCBD(const std::vector<uint8_t>& seed, uint8_t nonce, int n, int eta) {
    std::vector<uint8_t> nonceVec = {nonce};
    size_t bytesNeeded = static_cast<size_t>(n) * static_cast<size_t>(eta) / 4;
    std::vector<uint8_t> expanded = expandSeed(seed, nonceVec, bytesNeeded + 64);
    Poly p(n);

    size_t bitIdx = 0;
    auto getBit = [&](size_t idx) -> int {
        size_t bytePos = idx / 8;
        size_t bitPos = idx % 8;
        if (bytePos >= expanded.size()) return 0;
        return (expanded[bytePos] >> bitPos) & 1;
    };

    for (int i = 0; i < n; i++) {
        int a_sum = 0, b_sum = 0;
        for (int j = 0; j < eta; j++) {
            a_sum += getBit(bitIdx++);
        }
        for (int j = 0; j < eta; j++) {
            b_sum += getBit(bitIdx++);
        }
        p[i] = a_sum - b_sum;
    }
    return p;
}

// Sample Dilithium secret polynomial with coefficients in [-eta, eta]
static Poly sampleEta(const std::vector<uint8_t>& seed, uint8_t nonce, int n, int eta) {
    return sampleCBD(seed, nonce, n, eta);
}

// ============================================================================
// Dilithium-specific helpers
// ============================================================================

// Power2Round: decompose t into (t1, t0) where t = t1*2^d + t0
static void power2Round(int32_t r, int32_t& r1, int32_t& r0) {
    r1 = (r + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
    r0 = r - (r1 << DILITHIUM_D);
}

// HighBits and LowBits decomposition
static int32_t highBits(int32_t r) {
    int32_t r1;
    r = modQ(r, DILITHIUM_Q);
    r1 = (r + DILITHIUM_GAMMA2) / (2 * DILITHIUM_GAMMA2);
    if (r1 >= (DILITHIUM_Q - 1) / (2 * DILITHIUM_GAMMA2)) {
        r1 = 0;
    }
    return r1;
}

static int32_t lowBits(int32_t r) {
    r = modQ(r, DILITHIUM_Q);
    int32_t r1 = highBits(r);
    int32_t r0 = r - r1 * 2 * DILITHIUM_GAMMA2;
    if (r0 > DILITHIUM_GAMMA2) r0 -= DILITHIUM_Q;
    return r0;
}

// Infinity norm of a polynomial
static int32_t polyInfNorm(const Poly& p) {
    int32_t maxVal = 0;
    for (int32_t c : p) {
        int32_t absC = (c < 0) ? -c : c;
        if (absC > maxVal) maxVal = absC;
    }
    return maxVal;
}

// Pack polynomials into bytes for serialization
static std::vector<uint8_t> packPoly(const Poly& p, int bits) {
    std::vector<uint8_t> packed;
    size_t totalBits = p.size() * bits;
    packed.resize((totalBits + 7) / 8, 0);

    size_t bitIdx = 0;
    for (size_t i = 0; i < p.size(); i++) {
        uint32_t val = static_cast<uint32_t>(modQ(p[i], DILITHIUM_Q));
        for (int b = 0; b < bits; b++) {
            if (val & (1u << b)) {
                packed[bitIdx / 8] |= (1u << (bitIdx % 8));
            }
            bitIdx++;
        }
    }
    return packed;
}

// Unpack bytes into polynomial
static Poly unpackPoly(const std::vector<uint8_t>& data, size_t offset, int n, int bits) {
    Poly p(n, 0);
    size_t bitIdx = offset * 8;

    for (int i = 0; i < n; i++) {
        uint32_t val = 0;
        for (int b = 0; b < bits; b++) {
            size_t bytePos = bitIdx / 8;
            size_t bitPos = bitIdx % 8;
            if (bytePos < data.size() && (data[bytePos] & (1u << bitPos))) {
                val |= (1u << b);
            }
            bitIdx++;
        }
        p[i] = static_cast<int32_t>(val);
    }
    return p;
}

// ============================================================================
// CRYSTALS-Dilithium Key Generation
// ============================================================================

DilithiumKeyPair generateDilithiumKeyPair() {
    DilithiumKeyPair kp;

    // Generate random seed
    std::vector<uint8_t> seed = secureRandomBytes(32);

    // Expand seed into rho (public) and rho_prime (secret)
    std::vector<uint8_t> expanded = shake256(seed, 96);
    std::vector<uint8_t> rho(expanded.begin(), expanded.begin() + 32);
    std::vector<uint8_t> rhoPrime(expanded.begin() + 32, expanded.begin() + 96);

    // Generate public matrix A from rho
    // A is K x L matrix of polynomials
    std::vector<std::vector<Poly>> A(DILITHIUM_K, std::vector<Poly>(DILITHIUM_L));
    for (int i = 0; i < DILITHIUM_K; i++) {
        for (int j = 0; j < DILITHIUM_L; j++) {
            A[i][j] = sampleUniform(rho, static_cast<uint8_t>(i), static_cast<uint8_t>(j),
                                     DILITHIUM_N, DILITHIUM_Q);
        }
    }

    // Generate secret vectors s1 (L polynomials) and s2 (K polynomials)
    std::vector<Poly> s1(DILITHIUM_L), s2(DILITHIUM_K);
    for (int i = 0; i < DILITHIUM_L; i++) {
        s1[i] = sampleEta(rhoPrime, static_cast<uint8_t>(i), DILITHIUM_N, DILITHIUM_ETA);
    }
    for (int i = 0; i < DILITHIUM_K; i++) {
        s2[i] = sampleEta(rhoPrime, static_cast<uint8_t>(DILITHIUM_L + i), DILITHIUM_N, DILITHIUM_ETA);
    }

    // Compute t = A * s1 + s2
    std::vector<Poly> t(DILITHIUM_K);
    for (int i = 0; i < DILITHIUM_K; i++) {
        t[i] = polyNew(DILITHIUM_N);
        for (int j = 0; j < DILITHIUM_L; j++) {
            Poly product = polyMul(A[i][j], s1[j], DILITHIUM_N, DILITHIUM_Q);
            t[i] = polyAdd(t[i], product, DILITHIUM_Q);
        }
        t[i] = polyAdd(t[i], s2[i], DILITHIUM_Q);
    }

    // Power2Round t into (t1, t0)
    std::vector<Poly> t1(DILITHIUM_K), t0(DILITHIUM_K);
    for (int i = 0; i < DILITHIUM_K; i++) {
        t1[i] = polyNew(DILITHIUM_N);
        t0[i] = polyNew(DILITHIUM_N);
        for (int j = 0; j < DILITHIUM_N; j++) {
            power2Round(t[i][j], t1[i][j], t0[i][j]);
        }
    }

    // Pack public key: rho || t1
    kp.publicKey.clear();
    kp.publicKey.insert(kp.publicKey.end(), rho.begin(), rho.end());
    for (int i = 0; i < DILITHIUM_K; i++) {
        auto packed = packPoly(t1[i], 10);  // t1 needs 10 bits
        kp.publicKey.insert(kp.publicKey.end(), packed.begin(), packed.end());
    }
    kp.publicKey.resize(DILITHIUM_PUBLIC_KEY_SIZE, 0);

    // Pack secret key: rho || K || tr || s1 || s2 || t0
    // where K = H(rho || t1) and tr = H(pk)
    std::vector<uint8_t> pkHash = shake256(kp.publicKey, 64);
    std::vector<uint8_t> K(pkHash.begin(), pkHash.begin() + 32);
    std::vector<uint8_t> tr(pkHash.begin() + 32, pkHash.begin() + 64);

    kp.secretKey.clear();
    kp.secretKey.insert(kp.secretKey.end(), rho.begin(), rho.end());
    kp.secretKey.insert(kp.secretKey.end(), K.begin(), K.end());
    kp.secretKey.insert(kp.secretKey.end(), tr.begin(), tr.end());
    for (int i = 0; i < DILITHIUM_L; i++) {
        auto packed = packPoly(s1[i], 4);
        kp.secretKey.insert(kp.secretKey.end(), packed.begin(), packed.end());
    }
    for (int i = 0; i < DILITHIUM_K; i++) {
        auto packed = packPoly(s2[i], 4);
        kp.secretKey.insert(kp.secretKey.end(), packed.begin(), packed.end());
    }
    for (int i = 0; i < DILITHIUM_K; i++) {
        auto packed = packPoly(t0[i], 13);
        kp.secretKey.insert(kp.secretKey.end(), packed.begin(), packed.end());
    }
    kp.secretKey.resize(DILITHIUM_SECRET_KEY_SIZE, 0);

    kp.publicKeyHex = bytesToHex(kp.publicKey);
    kp.secretKeyHex = bytesToHex(kp.secretKey);

    return kp;
}

// ============================================================================
// CRYSTALS-Dilithium Signing
// ============================================================================

std::string dilithiumSign(const std::string& message, const std::string& secretKeyHex) {
    std::vector<uint8_t> sk = hexToBytes(secretKeyHex);
    std::vector<uint8_t> msg(message.begin(), message.end());
    auto sig = dilithiumSign(msg, sk);
    return sig;
}

std::string dilithiumSign(const std::vector<uint8_t>& message, const std::vector<uint8_t>& secretKey) {
    if (secretKey.size() < 96) {
        throw std::runtime_error("QuantumCrypto: Invalid Dilithium secret key size");
    }

    // Extract components from secret key
    std::vector<uint8_t> rho(secretKey.begin(), secretKey.begin() + 32);
    std::vector<uint8_t> K(secretKey.begin() + 32, secretKey.begin() + 64);
    std::vector<uint8_t> tr(secretKey.begin() + 64, secretKey.begin() + 96);

    // Hash message with tr to get mu
    std::vector<uint8_t> muInput;
    muInput.insert(muInput.end(), tr.begin(), tr.end());
    muInput.insert(muInput.end(), message.begin(), message.end());
    std::vector<uint8_t> mu = shake256(muInput, 64);

    // Reconstruct A from rho
    std::vector<std::vector<Poly>> A(DILITHIUM_K, std::vector<Poly>(DILITHIUM_L));
    for (int i = 0; i < DILITHIUM_K; i++) {
        for (int j = 0; j < DILITHIUM_L; j++) {
            A[i][j] = sampleUniform(rho, static_cast<uint8_t>(i), static_cast<uint8_t>(j),
                                     DILITHIUM_N, DILITHIUM_Q);
        }
    }

    // Reconstruct s1 and s2 from secret key
    size_t offset = 96;
    std::vector<Poly> s1(DILITHIUM_L), s2(DILITHIUM_K);
    size_t polyPackedSize4 = (DILITHIUM_N * 4 + 7) / 8;
    for (int i = 0; i < DILITHIUM_L; i++) {
        s1[i] = unpackPoly(secretKey, offset, DILITHIUM_N, 4);
        offset += polyPackedSize4;
    }
    for (int i = 0; i < DILITHIUM_K; i++) {
        s2[i] = unpackPoly(secretKey, offset, DILITHIUM_N, 4);
        offset += polyPackedSize4;
    }

    // Signing loop with rejection sampling
    uint16_t kappa = 0;
    const int MAX_ATTEMPTS = 1000;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        // Generate masking vector y
        std::vector<uint8_t> rhoPrimeInput;
        rhoPrimeInput.insert(rhoPrimeInput.end(), K.begin(), K.end());
        rhoPrimeInput.insert(rhoPrimeInput.end(), mu.begin(), mu.end());
        rhoPrimeInput.push_back(static_cast<uint8_t>(kappa & 0xFF));
        rhoPrimeInput.push_back(static_cast<uint8_t>((kappa >> 8) & 0xFF));
        std::vector<uint8_t> rhoPrime = shake256(rhoPrimeInput, 64);

        std::vector<Poly> y(DILITHIUM_L);
        for (int i = 0; i < DILITHIUM_L; i++) {
            y[i] = polyNew(DILITHIUM_N);
            std::vector<uint8_t> yNonce = {static_cast<uint8_t>(i), static_cast<uint8_t>(kappa & 0xFF)};
            auto yExpanded = expandSeed(rhoPrime, yNonce, DILITHIUM_N * 3);
            for (int j = 0; j < DILITHIUM_N; j++) {
                size_t idx = j * 3;
                if (idx + 2 < yExpanded.size()) {
                    int32_t val = static_cast<int32_t>(yExpanded[idx]) |
                                 (static_cast<int32_t>(yExpanded[idx + 1]) << 8) |
                                 (static_cast<int32_t>(yExpanded[idx + 2] & 0x0F) << 16);
                    y[i][j] = barrettReduceDilithium(val) - DILITHIUM_GAMMA1;
                }
            }
        }

        // Compute w = A * y
        std::vector<Poly> w(DILITHIUM_K);
        for (int i = 0; i < DILITHIUM_K; i++) {
            w[i] = polyNew(DILITHIUM_N);
            for (int j = 0; j < DILITHIUM_L; j++) {
                Poly product = polyMul(A[i][j], y[j], DILITHIUM_N, DILITHIUM_Q);
                w[i] = polyAdd(w[i], product, DILITHIUM_Q);
            }
        }

        // Compute w1 = HighBits(w)
        std::vector<Poly> w1(DILITHIUM_K);
        for (int i = 0; i < DILITHIUM_K; i++) {
            w1[i] = polyNew(DILITHIUM_N);
            for (int j = 0; j < DILITHIUM_N; j++) {
                w1[i][j] = highBits(w[i][j]);
            }
        }

        // Compute challenge c from H(mu || w1)
        std::vector<uint8_t> challengeInput;
        challengeInput.insert(challengeInput.end(), mu.begin(), mu.end());
        for (int i = 0; i < DILITHIUM_K; i++) {
            auto packed = packPoly(w1[i], 6);
            challengeInput.insert(challengeInput.end(), packed.begin(), packed.end());
        }
        std::vector<uint8_t> challengeHash = shake256(challengeInput, 32);

        // Expand challenge hash into a sparse polynomial c
        Poly c = polyNew(DILITHIUM_N);
        // Set TAU positions to +/-1 based on challenge hash
        for (int i = 0; i < DILITHIUM_TAU && i < 32; i++) {
            size_t pos = challengeHash[i] % DILITHIUM_N;
            c[pos] = (challengeHash[i] & 0x80) ? -1 : 1;
        }

        // Compute z = y + c*s1
        std::vector<Poly> z(DILITHIUM_L);
        bool reject = false;
        for (int i = 0; i < DILITHIUM_L; i++) {
            Poly cs1 = polyMul(c, s1[i], DILITHIUM_N, DILITHIUM_Q);
            z[i] = polyAdd(y[i], cs1, DILITHIUM_Q);

            // Check z infinity norm < GAMMA1 - beta
            int32_t beta = DILITHIUM_TAU * DILITHIUM_ETA;
            if (polyInfNorm(z[i]) >= DILITHIUM_GAMMA1 - beta) {
                reject = true;
                break;
            }
        }

        if (reject) {
            kappa++;
            continue;
        }

        // Check low bits of w - c*s2
        bool lowBitsReject = false;
        for (int i = 0; i < DILITHIUM_K; i++) {
            Poly cs2 = polyMul(c, s2[i], DILITHIUM_N, DILITHIUM_Q);
            Poly r = polySub(w[i], cs2, DILITHIUM_Q);
            for (int j = 0; j < DILITHIUM_N; j++) {
                int32_t lb = lowBits(r[j]);
                int32_t beta = DILITHIUM_TAU * DILITHIUM_ETA;
                if (lb < 0) lb = -lb;
                if (lb >= DILITHIUM_GAMMA2 - beta) {
                    lowBitsReject = true;
                    break;
                }
            }
            if (lowBitsReject) break;
        }

        if (lowBitsReject) {
            kappa++;
            continue;
        }

        // Signature accepted! Pack: challengeHash || z
        std::vector<uint8_t> signature;
        signature.insert(signature.end(), challengeHash.begin(), challengeHash.end());
        for (int i = 0; i < DILITHIUM_L; i++) {
            auto packed = packPoly(z[i], 20);  // z needs 20 bits
            signature.insert(signature.end(), packed.begin(), packed.end());
        }
        signature.resize(DILITHIUM_SIGNATURE_SIZE, 0);

        return bytesToHex(signature);
    }

    throw std::runtime_error("QuantumCrypto: Dilithium signing failed after maximum attempts");
}

// ============================================================================
// CRYSTALS-Dilithium Verification
// ============================================================================

bool dilithiumVerify(const std::string& message, const std::string& signatureHex,
                     const std::string& publicKeyHex) {
    try {
        std::vector<uint8_t> pk = hexToBytes(publicKeyHex);
        std::vector<uint8_t> sig = hexToBytes(signatureHex);
        std::vector<uint8_t> msg(message.begin(), message.end());
        return dilithiumVerify(msg, sig, pk);
    } catch (...) {
        return false;
    }
}

bool dilithiumVerify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature,
                     const std::vector<uint8_t>& publicKey) {
    try {
        if (publicKey.size() < 32 || signature.size() < 32) {
            return false;
        }

        // Extract rho and t1 from public key
        std::vector<uint8_t> rho(publicKey.begin(), publicKey.begin() + 32);

        // Reconstruct A from rho
        std::vector<std::vector<Poly>> A(DILITHIUM_K, std::vector<Poly>(DILITHIUM_L));
        for (int i = 0; i < DILITHIUM_K; i++) {
            for (int j = 0; j < DILITHIUM_L; j++) {
                A[i][j] = sampleUniform(rho, static_cast<uint8_t>(i), static_cast<uint8_t>(j),
                                         DILITHIUM_N, DILITHIUM_Q);
            }
        }

        // Unpack t1 from public key
        std::vector<Poly> t1(DILITHIUM_K);
        size_t offset = 32;
        size_t polyPackedSize10 = (DILITHIUM_N * 10 + 7) / 8;
        for (int i = 0; i < DILITHIUM_K; i++) {
            t1[i] = unpackPoly(publicKey, offset, DILITHIUM_N, 10);
            offset += polyPackedSize10;
        }

        // Extract challenge hash and z from signature
        std::vector<uint8_t> challengeHash(signature.begin(), signature.begin() + 32);

        // Unpack z from signature
        std::vector<Poly> z(DILITHIUM_L);
        offset = 32;
        size_t polyPackedSize20 = (DILITHIUM_N * 20 + 7) / 8;
        for (int i = 0; i < DILITHIUM_L; i++) {
            z[i] = unpackPoly(signature, offset, DILITHIUM_N, 20);
            offset += polyPackedSize20;
        }

        // Check z infinity norm
        for (int i = 0; i < DILITHIUM_L; i++) {
            int32_t beta = DILITHIUM_TAU * DILITHIUM_ETA;
            if (polyInfNorm(z[i]) >= DILITHIUM_GAMMA1 - beta) {
                return false;
            }
        }

        // Reconstruct challenge polynomial c from challengeHash
        Poly c = polyNew(DILITHIUM_N);
        for (int i = 0; i < DILITHIUM_TAU && i < 32; i++) {
            size_t pos = challengeHash[i] % DILITHIUM_N;
            c[pos] = (challengeHash[i] & 0x80) ? -1 : 1;
        }

        // Compute w' = A*z - c*t1*2^d
        std::vector<Poly> wPrime(DILITHIUM_K);
        for (int i = 0; i < DILITHIUM_K; i++) {
            wPrime[i] = polyNew(DILITHIUM_N);
            // A*z
            for (int j = 0; j < DILITHIUM_L; j++) {
                Poly product = polyMul(A[i][j], z[j], DILITHIUM_N, DILITHIUM_Q);
                wPrime[i] = polyAdd(wPrime[i], product, DILITHIUM_Q);
            }
            // Subtract c*t1*2^d
            Poly t1Scaled = polyNew(DILITHIUM_N);
            for (int j = 0; j < DILITHIUM_N; j++) {
                t1Scaled[j] = modQ(static_cast<int64_t>(t1[i][j]) << DILITHIUM_D, DILITHIUM_Q);
            }
            Poly ct1 = polyMul(c, t1Scaled, DILITHIUM_N, DILITHIUM_Q);
            wPrime[i] = polySub(wPrime[i], ct1, DILITHIUM_Q);
        }

        // Compute w1' = HighBits(w')
        std::vector<Poly> w1Prime(DILITHIUM_K);
        for (int i = 0; i < DILITHIUM_K; i++) {
            w1Prime[i] = polyNew(DILITHIUM_N);
            for (int j = 0; j < DILITHIUM_N; j++) {
                w1Prime[i][j] = highBits(wPrime[i][j]);
            }
        }

        // Compute mu = H(H(pk) || message)
        std::vector<uint8_t> pkHashFull = shake256(publicKey, 64);
        std::vector<uint8_t> tr(pkHashFull.begin() + 32, pkHashFull.begin() + 64);
        std::vector<uint8_t> muInput;
        muInput.insert(muInput.end(), tr.begin(), tr.end());
        muInput.insert(muInput.end(), message.begin(), message.end());
        std::vector<uint8_t> mu = shake256(muInput, 64);

        // Recompute challenge from mu and w1'
        std::vector<uint8_t> challengeInput;
        challengeInput.insert(challengeInput.end(), mu.begin(), mu.end());
        for (int i = 0; i < DILITHIUM_K; i++) {
            auto packed = packPoly(w1Prime[i], 6);
            challengeInput.insert(challengeInput.end(), packed.begin(), packed.end());
        }
        std::vector<uint8_t> challengeHashPrime = shake256(challengeInput, 32);

        // Verify: challengeHash == challengeHash'
        return challengeHash == challengeHashPrime;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// CRYSTALS-Kyber Key Generation
// ============================================================================

KyberKeyPair generateKyberKeyPair() {
    KyberKeyPair kp;

    // Generate random seed
    std::vector<uint8_t> seed = secureRandomBytes(32);
    std::vector<uint8_t> expanded = shake256(seed, 64);
    std::vector<uint8_t> rho(expanded.begin(), expanded.begin() + 32);
    std::vector<uint8_t> sigma(expanded.begin() + 32, expanded.end());

    // Generate public matrix A from rho
    std::vector<std::vector<Poly>> A(KYBER_K_PARAM, std::vector<Poly>(KYBER_K_PARAM));
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        for (int j = 0; j < KYBER_K_PARAM; j++) {
            A[i][j] = sampleUniform(rho, static_cast<uint8_t>(i), static_cast<uint8_t>(j),
                                     KYBER_N, KYBER_Q);
        }
    }

    // Generate secret vector s and error vector e
    std::vector<Poly> s(KYBER_K_PARAM), e(KYBER_K_PARAM);
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        s[i] = sampleCBD(sigma, static_cast<uint8_t>(i), KYBER_N, KYBER_ETA1);
        e[i] = sampleCBD(sigma, static_cast<uint8_t>(KYBER_K_PARAM + i), KYBER_N, KYBER_ETA1);
    }

    // Compute t = A*s + e
    std::vector<Poly> t(KYBER_K_PARAM);
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        t[i] = polyNew(KYBER_N);
        for (int j = 0; j < KYBER_K_PARAM; j++) {
            Poly product = polyMul(A[i][j], s[j], KYBER_N, KYBER_Q);
            t[i] = polyAdd(t[i], product, KYBER_Q);
        }
        t[i] = polyAdd(t[i], e[i], KYBER_Q);
    }

    // Pack public key: rho || t
    kp.publicKey.clear();
    kp.publicKey.insert(kp.publicKey.end(), rho.begin(), rho.end());
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        auto packed = packPoly(t[i], 12);
        kp.publicKey.insert(kp.publicKey.end(), packed.begin(), packed.end());
    }
    kp.publicKey.resize(KYBER_PUBLIC_KEY_SIZE, 0);

    // Pack secret key: s || pk || H(pk) || z
    kp.secretKey.clear();
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        auto packed = packPoly(s[i], 12);
        kp.secretKey.insert(kp.secretKey.end(), packed.begin(), packed.end());
    }
    kp.secretKey.insert(kp.secretKey.end(), kp.publicKey.begin(), kp.publicKey.end());
    auto pkHash = shake256(kp.publicKey, 32);
    kp.secretKey.insert(kp.secretKey.end(), pkHash.begin(), pkHash.end());
    auto z = secureRandomBytes(32);
    kp.secretKey.insert(kp.secretKey.end(), z.begin(), z.end());
    kp.secretKey.resize(KYBER_SECRET_KEY_SIZE, 0);

    kp.publicKeyHex = bytesToHex(kp.publicKey);
    kp.secretKeyHex = bytesToHex(kp.secretKey);

    return kp;
}

// ============================================================================
// CRYSTALS-Kyber Encapsulation
// ============================================================================

KyberEncapsulation kyberEncapsulate(const std::string& publicKeyHex) {
    return kyberEncapsulate(hexToBytes(publicKeyHex));
}

KyberEncapsulation kyberEncapsulate(const std::vector<uint8_t>& publicKey) {
    KyberEncapsulation result;

    if (publicKey.size() < 32) {
        throw std::runtime_error("QuantumCrypto: Invalid Kyber public key");
    }

    // Extract rho and t from public key
    std::vector<uint8_t> rho(publicKey.begin(), publicKey.begin() + 32);

    // Reconstruct A
    std::vector<std::vector<Poly>> A(KYBER_K_PARAM, std::vector<Poly>(KYBER_K_PARAM));
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        for (int j = 0; j < KYBER_K_PARAM; j++) {
            A[i][j] = sampleUniform(rho, static_cast<uint8_t>(i), static_cast<uint8_t>(j),
                                     KYBER_N, KYBER_Q);
        }
    }

    // Unpack t
    std::vector<Poly> t(KYBER_K_PARAM);
    size_t offset = 32;
    size_t polyPackedSize12 = (KYBER_N * 12 + 7) / 8;
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        t[i] = unpackPoly(publicKey, offset, KYBER_N, 12);
        offset += polyPackedSize12;
    }

    // Generate random message m
    auto m = secureRandomBytes(32);

    // H(pk)
    auto pkHash = shake256(publicKey, 32);

    // (K_bar, r) = G(m || H(pk))
    std::vector<uint8_t> gInput;
    gInput.insert(gInput.end(), m.begin(), m.end());
    gInput.insert(gInput.end(), pkHash.begin(), pkHash.end());
    auto gOutput = shake256(gInput, 64);
    std::vector<uint8_t> KBar(gOutput.begin(), gOutput.begin() + 32);
    std::vector<uint8_t> r(gOutput.begin() + 32, gOutput.end());

    // Generate r, e1, e2 from r
    std::vector<Poly> rVec(KYBER_K_PARAM), e1(KYBER_K_PARAM);
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        rVec[i] = sampleCBD(r, static_cast<uint8_t>(i), KYBER_N, KYBER_ETA1);
        e1[i] = sampleCBD(r, static_cast<uint8_t>(KYBER_K_PARAM + i), KYBER_N, KYBER_ETA2);
    }
    Poly e2 = sampleCBD(r, static_cast<uint8_t>(2 * KYBER_K_PARAM), KYBER_N, KYBER_ETA2);

    // u = A^T * r + e1
    std::vector<Poly> u(KYBER_K_PARAM);
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        u[i] = polyNew(KYBER_N);
        for (int j = 0; j < KYBER_K_PARAM; j++) {
            // A^T[i][j] = A[j][i]
            Poly product = polyMul(A[j][i], rVec[j], KYBER_N, KYBER_Q);
            u[i] = polyAdd(u[i], product, KYBER_Q);
        }
        u[i] = polyAdd(u[i], e1[i], KYBER_Q);
    }

    // v = t^T * r + e2 + encode(m)
    Poly v = polyNew(KYBER_N);
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        Poly product = polyMul(t[i], rVec[i], KYBER_N, KYBER_Q);
        v = polyAdd(v, product, KYBER_Q);
    }
    v = polyAdd(v, e2, KYBER_Q);
    // Encode m: each bit of m maps to 0 or q/2
    for (int i = 0; i < KYBER_N && i / 8 < static_cast<int>(m.size()); i++) {
        if (m[i / 8] & (1 << (i % 8))) {
            v[i] = modQ(static_cast<int64_t>(v[i]) + (KYBER_Q + 1) / 2, KYBER_Q);
        }
    }

    // Pack ciphertext: u || v
    result.ciphertext.clear();
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        auto packed = packPoly(u[i], 10);
        result.ciphertext.insert(result.ciphertext.end(), packed.begin(), packed.end());
    }
    auto vPacked = packPoly(v, 4);
    result.ciphertext.insert(result.ciphertext.end(), vPacked.begin(), vPacked.end());
    result.ciphertext.resize(KYBER_CIPHERTEXT_SIZE, 0);

    // Shared secret = H(K_bar || H(ct))
    auto ctHash = shake256(result.ciphertext, 32);
    std::vector<uint8_t> ssInput;
    ssInput.insert(ssInput.end(), KBar.begin(), KBar.end());
    ssInput.insert(ssInput.end(), ctHash.begin(), ctHash.end());
    result.sharedSecret = shake256(ssInput, KYBER_SHARED_SECRET_SIZE);

    return result;
}

// ============================================================================
// CRYSTALS-Kyber Decapsulation
// ============================================================================

std::vector<uint8_t> kyberDecapsulate(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& secretKey) {
    if (secretKey.size() < KYBER_SECRET_KEY_SIZE || ciphertext.size() < KYBER_CIPHERTEXT_SIZE) {
        throw std::runtime_error("QuantumCrypto: Invalid Kyber key/ciphertext size");
    }

    // Extract s from secret key
    size_t sPackedSize = static_cast<size_t>(KYBER_K_PARAM) * (KYBER_N * 12 + 7) / 8;
    std::vector<Poly> s(KYBER_K_PARAM);
    size_t offset = 0;
    size_t polyPackedSize12 = (KYBER_N * 12 + 7) / 8;
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        s[i] = unpackPoly(secretKey, offset, KYBER_N, 12);
        offset += polyPackedSize12;
    }

    // Extract pk from secret key
    std::vector<uint8_t> pk(secretKey.begin() + sPackedSize,
                            secretKey.begin() + sPackedSize + KYBER_PUBLIC_KEY_SIZE);

    // Extract H(pk) and z
    offset = sPackedSize + KYBER_PUBLIC_KEY_SIZE;
    std::vector<uint8_t> pkHash(secretKey.begin() + offset, secretKey.begin() + offset + 32);
    std::vector<uint8_t> z(secretKey.begin() + offset + 32, secretKey.begin() + offset + 64);

    // Unpack u and v from ciphertext
    std::vector<Poly> u(KYBER_K_PARAM);
    size_t ctOffset = 0;
    size_t polyPackedSize10 = (KYBER_N * 10 + 7) / 8;
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        u[i] = unpackPoly(ciphertext, ctOffset, KYBER_N, 10);
        ctOffset += polyPackedSize10;
    }
    size_t polyPackedSize4 = (KYBER_N * 4 + 7) / 8;
    Poly v = unpackPoly(ciphertext, ctOffset, KYBER_N, 4);

    // Compute m' = v - s^T * u
    Poly mPoly = polyNew(KYBER_N);
    for (int i = 0; i < KYBER_K_PARAM; i++) {
        Poly product = polyMul(s[i], u[i], KYBER_N, KYBER_Q);
        mPoly = polyAdd(mPoly, product, KYBER_Q);
    }
    mPoly = polySub(v, mPoly, KYBER_Q);

    // Decode m' -> message bytes
    std::vector<uint8_t> mPrime(32, 0);
    for (int i = 0; i < KYBER_N && i / 8 < 32; i++) {
        // If coefficient is closer to q/2 than to 0, bit is 1
        int32_t val = modQ(mPoly[i], KYBER_Q);
        if (val > KYBER_Q / 4 && val < 3 * KYBER_Q / 4) {
            mPrime[i / 8] |= (1 << (i % 8));
        }
    }

    // Shared secret = H(K_bar || H(ct))
    // Recompute: (K_bar, r) = G(m' || H(pk))
    std::vector<uint8_t> gInput;
    gInput.insert(gInput.end(), mPrime.begin(), mPrime.end());
    gInput.insert(gInput.end(), pkHash.begin(), pkHash.end());
    auto gOutput = shake256(gInput, 64);
    std::vector<uint8_t> KBar(gOutput.begin(), gOutput.begin() + 32);

    auto ctHash = shake256(ciphertext, 32);
    std::vector<uint8_t> ssInput;
    ssInput.insert(ssInput.end(), KBar.begin(), KBar.end());
    ssInput.insert(ssInput.end(), ctHash.begin(), ctHash.end());

    return shake256(ssInput, KYBER_SHARED_SECRET_SIZE);
}

std::string kyberDecapsulateHex(const std::string& ciphertextHex, const std::string& secretKeyHex) {
    auto ct = hexToBytes(ciphertextHex);
    auto sk = hexToBytes(secretKeyHex);
    auto ss = kyberDecapsulate(ct, sk);
    return bytesToHex(ss);
}

// ============================================================================
// Quantum-resistant address generation
// ============================================================================

std::string generateQuantumAddress(const std::string& dilithiumPublicKeyHex, bool testnet) {
    // Hash the Dilithium public key with SHA3-256 (quantum-safe hash)
    std::string hash = sha3_256(dilithiumPublicKeyHex);

    // Use first 40 hex chars (20 bytes) of the hash
    std::string addressHash = hash.substr(0, 40);

    // Prefix: qGXC for mainnet quantum addresses, qtGXC for testnet
    std::string prefix = testnet ? "qtGXC" : "qGXC";

    return prefix + addressHash;
}

// ============================================================================
// Key validation
// ============================================================================

bool isValidDilithiumPublicKey(const std::string& publicKeyHex) {
    return publicKeyHex.length() == DILITHIUM_PUBLIC_KEY_SIZE * 2;
}

bool isValidDilithiumSecretKey(const std::string& secretKeyHex) {
    return secretKeyHex.length() == DILITHIUM_SECRET_KEY_SIZE * 2;
}

bool isValidKyberPublicKey(const std::string& publicKeyHex) {
    return publicKeyHex.length() == KYBER_PUBLIC_KEY_SIZE * 2;
}

} // namespace QuantumCrypto
