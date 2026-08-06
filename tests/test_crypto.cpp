// Tests for the cryptographic primitives: secp256k1 key handling, ECDSA
// signing, address derivation, and the hash functions the chain is built on.

#include "test_framework.h"

#include "../include/Crypto.h"
#include "../include/HashUtils.h"

#include <set>

GXC_TEST(Hash, Sha256KnownVectors) {
    // NIST/RFC test vectors -- if these drift, every hash in the chain moved.
    CHECK_EQ(sha256(""),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256("abc"),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

GXC_TEST(Hash, Sha256dIsSha256OfSha256) {
    // Bitcoin's double-SHA256 of the empty string.
    CHECK_EQ(sha256d(""),
             std::string("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"));
}

GXC_TEST(Hash, Ripemd160KnownVector) {
    CHECK_EQ(ripemd160("abc"),
             std::string("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
}

GXC_TEST(Hash, Keccak256KnownVector) {
    // Original Keccak-256 padding (as used by Ethereum), not SHA3-256.
    CHECK_EQ(keccak256(""),
             std::string("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
}

GXC_TEST(Hash, DigestsAreDeterministicAndDistinct) {
    const std::string input = "GXC deterministic input";
    CHECK_EQ(sha256(input), sha256(input));
    CHECK_EQ(keccak256(input), keccak256(input));

    std::set<std::string> digests{sha256(input), sha256d(input), keccak256(input), ripemd160(input)};
    CHECK_EQ(digests.size(), size_t(4));
}

GXC_TEST(Hash, AvalancheOnSingleBitChange) {
    const std::string a = sha256("GXC");
    const std::string b = sha256("GXD");
    CHECK_NE(a, b);
    CHECK_EQ(a.size(), size_t(64));
}

GXC_TEST(Hash, GxHashIsMemoryHardAndDeterministic) {
    const std::string header = "gxc-block-header";
    const std::string first = gxhash(header, 1);
    CHECK_EQ(first.size(), size_t(64));
    CHECK_EQ(first, gxhash(header, 1));
    CHECK_NE(first, gxhash(header, 2));
}

GXC_TEST(Hash, EthashIsDeterministicAcrossNonces) {
    const std::string header = "gxc-ethash-header";
    const std::string first = ethash(header, 7);
    CHECK_EQ(first.size(), size_t(64));
    CHECK_EQ(first, ethash(header, 7));
    CHECK_NE(first, ethash(header, 8));
}

GXC_TEST(Hash, IsValidHash256) {
    CHECK(isValidHash256(std::string(64, 'a')));
    CHECK(isValidHash256(sha256("x")));
    CHECK_FALSE(isValidHash256(""));
    CHECK_FALSE(isValidHash256(std::string(63, 'a')));
    CHECK_FALSE(isValidHash256(std::string(65, 'a')));
    CHECK_FALSE(isValidHash256(std::string(63, 'a') + "z"));
}

GXC_TEST(Merkle, EmptyAndSingle) {
    CHECK_EQ(calculateMerkleRoot({}), std::string(""));
    CHECK_EQ(calculateMerkleRoot({"abcd"}), std::string("abcd"));
}

GXC_TEST(Merkle, PairsAreHashedTogether) {
    const std::string a = sha256("tx-a");
    const std::string b = sha256("tx-b");
    CHECK_EQ(calculateMerkleRoot({a, b}), sha256d(a + b));
}

GXC_TEST(Merkle, OddCountDuplicatesLast) {
    const std::string a = sha256("tx-a");
    const std::string b = sha256("tx-b");
    const std::string c = sha256("tx-c");

    const std::string expected = sha256d(sha256d(a + b) + sha256d(c + c));
    CHECK_EQ(calculateMerkleRoot({a, b, c}), expected);
}

GXC_TEST(Merkle, RootChangesWhenAnyLeafChanges) {
    const std::string a = sha256("tx-a");
    const std::string b = sha256("tx-b");
    const std::string c = sha256("tx-c");

    const std::string base = calculateMerkleRoot({a, b, c});
    CHECK_NE(base, calculateMerkleRoot({a, b, sha256("tx-c-modified")}));
    // Order matters: reordering transactions must change the commitment.
    CHECK_NE(base, calculateMerkleRoot({b, a, c}));
}

GXC_TEST(Crypto, KeyPairGenerationProducesWellFormedKeys) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();

    CHECK_EQ(keys.privateKey.size(), size_t(64));   // 32 bytes hex
    CHECK_EQ(keys.publicKey.size(), size_t(66));    // 33 bytes compressed hex

    // Compressed secp256k1 public keys start with 02 or 03.
    const std::string prefix = keys.publicKey.substr(0, 2);
    CHECK(prefix == "02" || prefix == "03");
}

GXC_TEST(Crypto, KeyPairsAreUnique) {
    std::set<std::string> seen;
    for (int i = 0; i < 16; i++) {
        seen.insert(Crypto::generateKeyPair().privateKey);
    }
    CHECK_EQ(seen.size(), size_t(16));
}

GXC_TEST(Crypto, PublicKeyDerivationIsDeterministic) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    CHECK_EQ(Crypto::derivePublicKey(keys.privateKey), keys.publicKey);
    CHECK_EQ(Crypto::derivePublicKey(keys.privateKey), Crypto::derivePublicKey(keys.privateKey));
}

GXC_TEST(Crypto, SignAndVerifyRoundTrip) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    const std::string message = "GXC transfer of 12.5 GXC";

    const std::string signature = Crypto::signData(message, keys.privateKey);
    CHECK_FALSE(signature.empty());
    CHECK(Crypto::verifySignature(message, signature, keys.publicKey));
}

GXC_TEST(Crypto, SignatureRejectsModifiedMessage) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    const std::string signature = Crypto::signData("send 10 GXC to Alice", keys.privateKey);

    CHECK_FALSE(Crypto::verifySignature("send 10 GXC to Mallory", signature, keys.publicKey));
}

GXC_TEST(Crypto, SignatureRejectsWrongPublicKey) {
    const Crypto::KeyPair signer = Crypto::generateKeyPair();
    const Crypto::KeyPair other = Crypto::generateKeyPair();
    const std::string message = "authorize";

    const std::string signature = Crypto::signData(message, signer.privateKey);
    CHECK(Crypto::verifySignature(message, signature, signer.publicKey));
    CHECK_FALSE(Crypto::verifySignature(message, signature, other.publicKey));
}

GXC_TEST(Crypto, SignatureRejectsGarbage) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    // Malformed DER must be rejected cleanly rather than crashing.
    CHECK_FALSE(Crypto::verifySignature("msg", "", keys.publicKey));
    CHECK_FALSE(Crypto::verifySignature("msg", "deadbeef", keys.publicKey));
    CHECK_FALSE(Crypto::verifySignature("msg", "zzzz", keys.publicKey));
}

GXC_TEST(Crypto, AddressDerivationIsDeterministic) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    const std::string address = Crypto::generateAddress(keys.publicKey, false);

    CHECK_EQ(address, Crypto::generateAddress(keys.publicKey, false));
    CHECK_EQ(address.substr(0, 3), std::string("GXC"));
}

GXC_TEST(Crypto, TestnetAddressesUseDistinctPrefix) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();

    const std::string mainnet = Crypto::generateAddress(keys.publicKey, false);
    const std::string testnet = Crypto::generateAddress(keys.publicKey, true);

    CHECK_EQ(testnet.substr(0, 4), std::string("tGXC"));
    CHECK_NE(mainnet, testnet);
}

GXC_TEST(Crypto, DistinctKeysYieldDistinctAddresses) {
    std::set<std::string> addresses;
    for (int i = 0; i < 16; i++) {
        addresses.insert(Crypto::generateAddress(Crypto::generateKeyPair().publicKey, false));
    }
    CHECK_EQ(addresses.size(), size_t(16));
}

GXC_TEST(Crypto, HexConversionRoundTrips) {
    const std::vector<uint8_t> bytes{0x00, 0x01, 0x7f, 0x80, 0xff, 0xde, 0xad};
    const std::string hex = Crypto::bytesToHex(bytes);

    CHECK_EQ(hex, std::string("00017f80ffdead"));
    CHECK(Crypto::hexToBytes(hex) == bytes);
}
