// End-to-end checks that each mining algorithm actually works as designed:
// that it produces a hash meeting the declared target, that the resulting block
// passes the same validation a peer would apply, and that the three algorithms
// are genuinely distinct functions rather than aliases of one another.

#include "test_framework.h"

#include "../include/Block.h"
#include "../include/Config.h"
#include "../include/Crypto.h"
#include "../include/HashUtils.h"
#include "../include/arith_uint256.h"

#include <chrono>
#include <set>

namespace {

const char* kMiner = "GXCminer000000000000000000000000000";

/** Build an unmined block of `type` carrying a coinbase. */
Block candidateBlock(BlockType type, uint32_t index = 1) {
    Config::setNetworkMode(true); // testnet target: findable on a CPU

    Block block(index, Crypto::sha256("prev-" + std::to_string(index)), type);
    block.setMinerAddress(kMiner);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.addTransactionUnchecked(Transaction(kMiner, 50.0));
    return block;
}

/**
 * Everything a receiving node checks about a mined block, short of chain
 * context: the hash is the one the contents produce, the merkle root matches
 * the transactions, the hash clears the target, and the work receipt binds the
 * coinbase to this block.
 */
void checkBlockIsSelfConsistent(const Block& block) {
    CHECK(block.hasValidHash());
    CHECK(block.hasValidMerkleRoot());
    CHECK(meetsTarget(block.getHash(), block.getDifficulty(), true));
    CHECK(block.verifyWorkReceipt());
}

} // namespace

// ---------------------------------------------------------------------------
// Each algorithm, mined end to end
// ---------------------------------------------------------------------------

GXC_TEST(Mining, Sha256ProducesAValidBlock) {
    Block block = candidateBlock(BlockType::POW_SHA256);

    CHECK(block.mineBlock(1.0, 2000000));
    checkBlockIsSelfConsistent(block);
    CHECK(block.getBlockType() == BlockType::POW_SHA256);
}

GXC_TEST(Mining, EthashProducesAValidBlock) {
    Block block = candidateBlock(BlockType::POW_ETHASH);

    CHECK(block.mineBlock(1.0, 200000));
    checkBlockIsSelfConsistent(block);
    CHECK(block.getBlockType() == BlockType::POW_ETHASH);
}

GXC_TEST(Mining, GxHashProducesAValidBlock) {
    Block block = candidateBlock(BlockType::POW_GXHASH);

    // GXHash is memory-hard by design (Argon2id, 64 MiB), so it is orders of
    // magnitude slower per attempt. The testnet target is easy enough that a
    // small budget suffices.
    CHECK(block.mineBlock(1.0, 2000));
    checkBlockIsSelfConsistent(block);
    CHECK(block.getBlockType() == BlockType::POW_GXHASH);
}

// ---------------------------------------------------------------------------
// The algorithms are distinct
// ---------------------------------------------------------------------------

GXC_TEST(Mining, AlgorithmsProduceDifferentHashesForTheSameHeader) {
    const std::string previous = Crypto::sha256("shared-prev");

    Block sha(1, previous, BlockType::POW_SHA256);
    Block eth(1, previous, BlockType::POW_ETHASH);
    Block gxh(1, previous, BlockType::POW_GXHASH);
    Block pos(1, previous, BlockType::POS);

    // Pin every other header field so the algorithm is the only difference.
    for (Block* b : {&sha, &eth, &gxh, &pos}) {
        b->setTimestamp(1700000000);
        b->setNonce(12345);
        b->setMerkleRoot(Crypto::sha256("root"));
    }

    std::set<std::string> hashes{
        sha.calculateHash(), eth.calculateHash(),
        gxh.calculateHash(), pos.calculateHash()};

    CHECK_EQ(hashes.size(), size_t(4));
}

GXC_TEST(Mining, EveryAlgorithmIsDeterministic) {
    const std::string previous = Crypto::sha256("determinism");

    for (BlockType type : {BlockType::POW_SHA256, BlockType::POW_ETHASH,
                           BlockType::POW_GXHASH, BlockType::POS}) {
        Block block(3, previous, type);
        block.setTimestamp(1700000000);
        block.setNonce(99);
        block.setMerkleRoot(Crypto::sha256("root"));

        const std::string first = block.calculateHash();
        CHECK_EQ(first.size(), size_t(64));
        CHECK_EQ(block.calculateHash(), first);
    }
}

GXC_TEST(Mining, NonceChangesTheHashForEveryAlgorithm) {
    for (BlockType type : {BlockType::POW_SHA256, BlockType::POW_ETHASH,
                           BlockType::POW_GXHASH}) {
        Block block(1, Crypto::sha256("nonce-test"), type);
        block.setTimestamp(1700000000);
        block.setMerkleRoot(Crypto::sha256("root"));

        block.setNonce(1);
        const std::string a = block.calculateHash();
        block.setNonce(2);
        const std::string b = block.calculateHash();

        // If the nonce did not feed the hash, mining could never terminate.
        CHECK_NE(a, b);
    }
}

// ---------------------------------------------------------------------------
// Mined blocks survive the wire
// ---------------------------------------------------------------------------

GXC_TEST(Mining, MinedBlocksRoundTripThroughSerializationForEveryAlgorithm) {
    struct Case { BlockType type; uint64_t budget; };
    const Case cases[] = {
        {BlockType::POW_SHA256, 2000000},
        {BlockType::POW_ETHASH, 200000},
        {BlockType::POW_GXHASH, 2000},
    };

    for (const Case& c : cases) {
        Block block = candidateBlock(c.type, 4);
        CHECK(block.mineBlock(1.0, c.budget));

        const Block restored = Block::deserialize(block.serialize());

        CHECK_EQ(restored.getHash(), block.getHash());
        CHECK(restored.getBlockType() == c.type);
        // A peer must reach the same verdict on the received block.
        checkBlockIsSelfConsistent(restored);
    }
}

// ---------------------------------------------------------------------------
// Performance characteristics the design depends on
// ---------------------------------------------------------------------------

GXC_TEST(Mining, EthashCacheIsReusedAcrossNonces) {
    // Ethash's cache depends only on the header, not the nonce. If it were
    // rebuilt per attempt, the ~65k keccak invocations it costs would dominate
    // and mining would be unusable. Hashing many nonces over one header must
    // therefore cost far less than the first call plus a linear rebuild.
    const std::string header = "gxc-ethash-cache-reuse";

    const auto startFirst = std::chrono::steady_clock::now();
    (void)ethash(header, 0);
    const auto firstCall = std::chrono::steady_clock::now() - startFirst;

    const auto startRest = std::chrono::steady_clock::now();
    for (uint64_t nonce = 1; nonce <= 50; nonce++) {
        (void)ethash(header, nonce);
    }
    const auto fiftyCalls = std::chrono::steady_clock::now() - startRest;

    // Fifty cached hashes must beat fifty cache rebuilds by a wide margin.
    // Comparing against the first (cache-building) call keeps this robust on
    // slow or contended CI machines.
    CHECK(fiftyCalls < firstCall * 25);
}

GXC_TEST(Mining, GxHashIsMemoryHard) {
    // Argon2id at 64 MiB is deliberately expensive. It should be markedly
    // slower per attempt than SHA-256 -- that cost is the ASIC resistance.
    const std::string header = "gxc-memory-hardness";

    const auto shaStart = std::chrono::steady_clock::now();
    for (int i = 0; i < 100; i++) {
        (void)sha256d(header + std::to_string(i));
    }
    const auto shaTime = std::chrono::steady_clock::now() - shaStart;

    const auto gxStart = std::chrono::steady_clock::now();
    (void)gxhash(header, 0);
    const auto gxTime = std::chrono::steady_clock::now() - gxStart;

    CHECK(gxTime > shaTime);
}

// ---------------------------------------------------------------------------
// Failure modes
// ---------------------------------------------------------------------------

GXC_TEST(Mining, MiningFailsClosedOnAnExhaustedBudget) {
    Config::setNetworkMode(false); // mainnet target: not findable in a few tries

    for (BlockType type : {BlockType::POW_SHA256, BlockType::POW_ETHASH,
                           BlockType::POW_GXHASH}) {
        Block block(1, Crypto::sha256("hard"), type);
        block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);

        CHECK_FALSE(block.mineBlock(1000.0, 16));
        // An unmined block must not carry a receipt.
        CHECK(block.getWorkReceiptHash().empty());
    }

    Config::setNetworkMode(true);
}

GXC_TEST(Mining, TamperingWithAMinedBlockIsDetectedForEveryAlgorithm) {
    struct Case { BlockType type; uint64_t budget; };
    const Case cases[] = {
        {BlockType::POW_SHA256, 2000000},
        {BlockType::POW_ETHASH, 200000},
        {BlockType::POW_GXHASH, 2000},
    };

    for (const Case& c : cases) {
        Block block = candidateBlock(c.type, 6);
        CHECK(block.mineBlock(1.0, c.budget));
        CHECK(block.hasValidHash());

        // Slipping an extra transaction into a mined block leaves the stored
        // merkle root describing the old set, so the merkle check catches it.
        Block tampered = block;
        tampered.addTransactionUnchecked(Transaction("GXCattacker00000000000000000000000", 50.0));

        CHECK_FALSE(tampered.hasValidMerkleRoot());

        // Repairing the root to match the new set then breaks the header hash
        // and the work receipt, because both commit to it. There is no way to
        // satisfy all three without redoing the work -- which is why block
        // validation checks the merkle root and the header hash separately.
        tampered.calculateMerkleRoot();
        CHECK(tampered.hasValidMerkleRoot());
        CHECK_FALSE(tampered.hasValidHash());
        CHECK_FALSE(tampered.verifyWorkReceipt());
    }
}

GXC_TEST(Mining, ClaimedHashWithoutWorkIsRejected) {
    // The classic forgery: present a hash with plenty of leading zeros that the
    // block's own contents do not produce.
    Block block = candidateBlock(BlockType::POW_SHA256);
    block.setHash(std::string(64, '0'));

    CHECK(meetsTarget(block.getHash(), 1.0, true)); // it clears the target...
    CHECK_FALSE(block.hasValidHash());              // ...but it is not the real hash
}
