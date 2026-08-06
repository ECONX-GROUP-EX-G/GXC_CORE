// Tests for block structure, mining, the proof-of-work target predicate, and
// block serialization over the P2P wire.

#include "test_framework.h"

#include "../include/Block.h"
#include "../include/Config.h"
#include "../include/Crypto.h"
#include "../include/HashUtils.h"
#include "../include/arith_uint256.h"

namespace {

Block minedTestnetBlock(uint32_t index = 1) {
    Config::setNetworkMode(true);

    Block block(index, Crypto::sha256("previous-" + std::to_string(index)), BlockType::POW_SHA256);
    block.setMinerAddress("GXCminer000000000000000000000000000");
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    block.mineBlock(1.0, 1000000);
    return block;
}

} // namespace

GXC_TEST(Block, DefaultConstructionIsFullyInitialized) {
    Block block;

    CHECK_EQ(block.getIndex(), uint32_t(0));
    CHECK_EQ(block.getNonce(), uint64_t(0));
    CHECK_NEAR(block.getDifficulty(), 0.0, 1e-9);
    CHECK_EQ(block.getHash().size(), size_t(64));
    // Every member must be initialized: an uninitialized difficulty or reward
    // would make the header hash non-deterministic across runs.
    CHECK_NEAR(block.getBlockReward(), 0.0, 1e-9);
    CHECK_NEAR(block.getFeeBurnRate(), 0.0, 1e-9);
}

GXC_TEST(Block, HeaderHashIsDeterministic) {
    Block block(3, Crypto::sha256("prev"), BlockType::POW_SHA256);
    const std::string hash = block.calculateHash();

    CHECK_EQ(hash, block.calculateHash());
    CHECK_EQ(hash.size(), size_t(64));

    block.setNonce(1);
    CHECK_NE(block.calculateHash(), hash);
}

GXC_TEST(Block, HasValidHashDetectsTampering) {
    Block block = minedTestnetBlock();
    CHECK(block.hasValidHash());

    // A block claiming a hash that its contents do not produce must be caught.
    block.setHash(std::string(64, '0'));
    CHECK_FALSE(block.hasValidHash());
}

GXC_TEST(Block, MerkleRootTracksTransactions) {
    Block block(1, Crypto::sha256("prev"), BlockType::POW_SHA256);
    block.calculateMerkleRoot();
    const std::string empty = block.getMerkleRoot();

    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    block.calculateMerkleRoot();

    CHECK_NE(block.getMerkleRoot(), empty);
    CHECK(block.hasValidMerkleRoot());
}

GXC_TEST(Block, MerkleRootMismatchIsDetected) {
    Block block = minedTestnetBlock();
    CHECK(block.hasValidMerkleRoot());

    block.setMerkleRoot(Crypto::sha256("a-different-root"));
    CHECK_FALSE(block.hasValidMerkleRoot());
}

GXC_TEST(Block, AddTransactionRejectsInvalidTransactions) {
    Block block(1, Crypto::sha256("prev"), BlockType::POW_SHA256);

    Transaction empty;  // no outputs, no inputs, unsigned
    CHECK_FALSE(block.addTransaction(empty));
    CHECK_EQ(block.getTransactions().size(), size_t(0));

    Transaction coinbase("GXCminer000000000000000000000000000", 50.0);
    CHECK(block.addTransaction(coinbase));
    CHECK_EQ(block.getTransactions().size(), size_t(1));
}

GXC_TEST(Block, MiningFindsAHashUnderTheTarget) {
    Config::setNetworkMode(true);

    Block block(1, Crypto::sha256("prev"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));

    CHECK(block.mineBlock(1.0, 1000000));
    CHECK(meetsTarget(block.getHash(), 1.0, true));
    CHECK(block.hasValidHash());
}

GXC_TEST(Block, MiningRespectsTheAttemptBudget) {
    Config::setNetworkMode(false); // mainnet target: not findable in a few tries

    Block block(1, Crypto::sha256("prev"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);

    // Must return false rather than spinning forever -- the old implementation
    // looped unconditionally until it found a solution.
    CHECK_FALSE(block.mineBlock(1000.0, 64));

    Config::setNetworkMode(true);
}

GXC_TEST(Block, ProofOfStakeBlocksAreNotMined) {
    Block block(1, Crypto::sha256("prev"), BlockType::POS);
    CHECK_FALSE(block.mineBlock(1.0, 1000));
}

GXC_TEST(Block, PowAndPosCommitmentsDiffer) {
    Block block(1, Crypto::sha256("prev"), BlockType::POW_SHA256);
    block.setValidatorAddress("GXCvalidator00000000000000000000000");

    CHECK_EQ(block.calculatePowHash().size(), size_t(64));
    CHECK_EQ(block.calculatePosHash().size(), size_t(64));
    CHECK_NE(block.calculatePowHash(), block.calculatePosHash());

    // The PoS commitment excludes the nonce -- there is no search to bind to.
    const std::string pos = block.calculatePosHash();
    block.setNonce(block.getNonce() + 1);
    CHECK_EQ(block.calculatePosHash(), pos);
    CHECK_NE(block.calculatePowHash(), pos);
}

GXC_TEST(Block, PosSignatureVerifies) {
    const Crypto::KeyPair validator = Crypto::generateKeyPair();

    Block block(1, Crypto::sha256("prev"), BlockType::POS);
    block.setValidatorAddress(Crypto::generateAddress(validator.publicKey, true));
    block.setMinerPublicKey(validator.publicKey);

    const std::string signature = Crypto::signData(block.calculatePosHash(), validator.privateKey);
    block.setValidatorSignature(signature);

    CHECK(block.validateBlock());
    CHECK(block.validateBlock(signature));
}

GXC_TEST(Block, PosSignatureFromWrongValidatorIsRejected) {
    const Crypto::KeyPair validator = Crypto::generateKeyPair();
    const Crypto::KeyPair impostor = Crypto::generateKeyPair();

    Block block(1, Crypto::sha256("prev"), BlockType::POS);
    block.setValidatorAddress(Crypto::generateAddress(validator.publicKey, true));
    block.setMinerPublicKey(validator.publicKey);
    block.setValidatorSignature(Crypto::signData(block.calculatePosHash(), impostor.privateKey));

    // An earlier version returned true for any non-empty string, so an
    // unsigned block was indistinguishable from a signed one.
    CHECK_FALSE(block.validateBlock());
    CHECK_FALSE(block.validateBlock("not-a-signature"));
}

GXC_TEST(Block, PosSignatureDoesNotTransferBetweenBlocks) {
    const Crypto::KeyPair validator = Crypto::generateKeyPair();

    Block first(1, Crypto::sha256("prev-a"), BlockType::POS);
    first.setValidatorAddress(Crypto::generateAddress(validator.publicKey, true));
    first.setMinerPublicKey(validator.publicKey);
    const std::string signature = Crypto::signData(first.calculatePosHash(), validator.privateKey);
    first.setValidatorSignature(signature);
    CHECK(first.validateBlock());

    Block second(2, Crypto::sha256("prev-b"), BlockType::POS);
    second.setValidatorAddress(first.getValidatorAddress());
    second.setMinerPublicKey(validator.publicKey);
    second.setValidatorSignature(signature);

    CHECK_FALSE(second.validateBlock());
}

GXC_TEST(Block, PowBlocksAreNotValidatorSigned) {
    Block block = minedTestnetBlock();
    CHECK_FALSE(block.validateBlock("anything"));
}

// ---------------------------------------------------------------------------
// Proof-of-work target predicate
// ---------------------------------------------------------------------------

GXC_TEST(ProofOfWork, MalformedHashesNeverMeetTheTarget) {
    CHECK_FALSE(meetsTarget("", 1.0, true));
    CHECK_FALSE(meetsTarget("abc", 1.0, true));
    CHECK_FALSE(meetsTarget(std::string(64, 'z'), 1.0, true));
    CHECK_FALSE(meetsTarget(std::string(63, '0'), 1.0, true));
}

GXC_TEST(ProofOfWork, ZeroHashAlwaysMeetsAnyTarget) {
    CHECK(meetsTarget(std::string(64, '0'), 1.0, true));
    CHECK(meetsTarget(std::string(64, '0'), 1e9, false));
}

GXC_TEST(ProofOfWork, MaximalHashNeverMeetsTheTarget) {
    CHECK_FALSE(meetsTarget(std::string(64, 'f'), 1.0, false));
    CHECK_FALSE(meetsTarget(std::string(64, 'f'), 1.0, true));
}

GXC_TEST(ProofOfWork, TargetBoundaryIsInclusive) {
    const arith_uint256 target = DifficultyToTarget(1000.0, false);

    CHECK(meetsTarget(target.GetHex(), 1000.0, false));

    arith_uint256 justOver = target;
    ++justOver;
    CHECK_FALSE(meetsTarget(justOver.GetHex(), 1000.0, false));
}

// The bug this guards against was fatal: the validator compared leading hex
// zeros against the raw difficulty value, so the mainnet floor of 1000 demanded
// 1000 leading zeros in a 64-character hash. No block could ever satisfy it, and
// the mainnet chain could not advance past genesis.
GXC_TEST(ProofOfWork, MainnetFloorDifficultyIsSatisfiable) {
    const arith_uint256 target = DifficultyToTarget(1000.0, false);

    CHECK_FALSE(target.IsZero());
    CHECK(meetsTarget(target.GetHex(), 1000.0, false));

    // The target must leave a workable amount of the hash space available --
    // far more than a 1000-leading-zero requirement would.
    CHECK(target.bits() > 128);
}

GXC_TEST(ProofOfWork, MinerAndValidatorAgree) {
    Config::setNetworkMode(true);

    Block block(1, Crypto::sha256("prev"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));

    CHECK(block.mineBlock(1.0, 1000000));

    // Whatever the miner accepted, the validator must also accept. These two
    // used to use different difficulty semantics entirely.
    CHECK(meetsTarget(block.getHash(), block.getDifficulty(), true));
    CHECK(block.hasValidHash());
    CHECK(block.hasValidMerkleRoot());
}

GXC_TEST(ProofOfWork, HarderTargetsRejectMoreHashes) {
    // A hash that clears an easy target should not clear a much harder one.
    const std::string hash = DifficultyToTarget(16.0, false).GetHex();

    CHECK(meetsTarget(hash, 16.0, false));
    CHECK(meetsTarget(hash, 8.0, false));
    CHECK_FALSE(meetsTarget(hash, 1024.0, false));
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

GXC_TEST(BlockSerialization, RoundTripsAllHeaderFields) {
    Block original = minedTestnetBlock(42);
    original.setBlockReward(50.0);
    original.setFeeBurnRate(0.1);
    original.setPopReference("pop-ref-123");
    original.setChainWork("00000000000000000000000000000000000000000000000000000000deadbeef");
    original.setNBits(0x207fffff);

    const Block restored = Block::deserialize(original.serialize());

    CHECK_EQ(restored.getIndex(), original.getIndex());
    CHECK_EQ(restored.getPreviousHash(), original.getPreviousHash());
    CHECK_EQ(restored.getHash(), original.getHash());
    CHECK_EQ(restored.getMerkleRoot(), original.getMerkleRoot());
    CHECK_EQ(restored.getTimestamp(), original.getTimestamp());
    CHECK_EQ(restored.getNonce(), original.getNonce());
    CHECK(restored.getBlockType() == original.getBlockType());
    CHECK_EQ(restored.getMinerAddress(), original.getMinerAddress());
    CHECK_NEAR(restored.getDifficulty(), original.getDifficulty(), 1e-9);
    CHECK_EQ(restored.getWorkReceiptHash(), original.getWorkReceiptHash());
    CHECK_EQ(restored.getMinerPublicKey(), original.getMinerPublicKey());
    CHECK_EQ(restored.getChainWork(), original.getChainWork());
    CHECK_EQ(restored.getNBits(), original.getNBits());
    CHECK_EQ(restored.getPopReference(), original.getPopReference());
}

GXC_TEST(BlockSerialization, RoundTripsTransactions) {
    Block original = minedTestnetBlock(5);
    const Block restored = Block::deserialize(original.serialize());

    CHECK_EQ(restored.getTransactions().size(), original.getTransactions().size());
    CHECK_EQ(restored.getTransactions()[0].getHash(), original.getTransactions()[0].getHash());
    CHECK(restored.getTransactions()[0].isCoinbaseTransaction());
}

// A round-tripped block must still validate. If it did not, nothing received
// from a peer could ever be accepted -- which is the state the node was in when
// Block::serialize was declared but never implemented.
GXC_TEST(BlockSerialization, RestoredBlockStillValidates) {
    Block original = minedTestnetBlock(11);
    const Block restored = Block::deserialize(original.serialize());

    CHECK(restored.hasValidHash());
    CHECK(restored.hasValidMerkleRoot());
    CHECK(restored.verifyWorkReceipt());
    CHECK(meetsTarget(restored.getHash(), restored.getDifficulty(), true));
}

GXC_TEST(BlockSerialization, SerializationIsStable) {
    Block block = minedTestnetBlock(3);
    CHECK_EQ(block.serialize(), block.serialize());
    CHECK_EQ(Block::deserialize(block.serialize()).serialize(), block.serialize());
}

GXC_TEST(BlockSerialization, RejectsTruncatedPayload) {
    const std::string payload = minedTestnetBlock().serialize();

    CHECK_THROWS(Block::deserialize(""));
    CHECK_THROWS(Block::deserialize(payload.substr(0, payload.size() / 2)));
    CHECK_THROWS(Block::deserialize("garbage-without-length-prefix"));
}

GXC_TEST(BlockSerialization, RejectsOversizedLengthPrefix) {
    // A frame declaring a field far longer than the buffer must be rejected
    // rather than read out of bounds.
    CHECK_THROWS(Block::deserialize("99999999:short"));
    CHECK_THROWS(Block::deserialize("1:1|999999999999999999999:x"));
}

GXC_TEST(BlockSerialization, RejectsUnknownBlockType) {
    // Field 7 is the block type; 99 is not a valid BlockType.
    const std::string forged = "1:1|4:prev|4:hash|4:root|2:10|1:0|2:99|";
    CHECK_THROWS(Block::deserialize(forged));
}

GXC_TEST(BlockSerialization, HandlesEmptyStringFields) {
    Block block(1, "", BlockType::POW_SHA256);
    block.setMinerAddress("");
    block.setPopReference("");

    const Block restored = Block::deserialize(block.serialize());
    CHECK_EQ(restored.getPreviousHash(), std::string(""));
    CHECK_EQ(restored.getMinerAddress(), std::string(""));
    CHECK_EQ(restored.getIndex(), uint32_t(1));
}
