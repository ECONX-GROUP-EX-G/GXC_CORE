// Proof of Traceability (POT) and the Proof-of-Work Receipt.
//
// These are the two mechanisms that make GXC auditable, and they are the two
// most load-bearing invariants in the protocol:
//
//   POT           every non-coinbase transaction names the transaction it
//                 descends from, and the amount it inherited, and both must
//                 agree with its first input. Following prevTxHash backwards
//                 walks an unbroken chain of custody to a coinbase.
//
//   Work receipt  H(prev_hash || merkle_root || nonce || miner_pubkey ||
//                 difficulty || timestamp), carried on both the block and its
//                 coinbase. It ties every newly minted coin to the one specific
//                 proof-of-work solution that justified minting it.
//
// The tests below cover both the accepting and the rejecting direction. A
// verifier that only ever says "yes" is worse than no verifier at all -- that is
// exactly the state POT was in before, when it compared a field against itself.

#include "test_framework.h"

#include "../include/Block.h"
#include "../include/Config.h"
#include "../include/Crypto.h"
#include "../include/HashUtils.h"
#include "../include/transaction.h"

namespace {

/** Build a transaction that spends `parentHash` and correctly declares POT. */
Transaction traceableSpend(const std::string& parentHash, double parentAmount,
                           const std::string& recipient, double payout, double fee) {
    TransactionInput input;
    input.txHash = parentHash;
    input.outputIndex = 0;
    input.amount = parentAmount;

    TransactionOutput output;
    output.address = recipient;
    output.amount = payout;
    output.script = "OP_DUP OP_HASH160 " + recipient + " OP_EQUALVERIFY OP_CHECKSIG";

    std::vector<TransactionOutput> outputs{output};
    const double change = parentAmount - payout - fee;
    if (change > 1e-9) {
        TransactionOutput changeOutput;
        changeOutput.address = "GXCchange00000000000000000000000000";
        changeOutput.amount = change;
        outputs.push_back(changeOutput);
    }

    Transaction tx({input}, outputs, parentHash);
    tx.setFee(fee);
    tx.setReferencedAmount(parentAmount);
    return tx;
}

const char* kRecipient = "GXCrecipient0000000000000000000000";

} // namespace

// ---------------------------------------------------------------------------
// Proof of Traceability
// ---------------------------------------------------------------------------

GXC_TEST(Traceability, WellFormedSpendSatisfiesTheFormula) {
    const std::string parent = Crypto::sha256("parent-tx");
    Transaction tx = traceableSpend(parent, 100.0, kRecipient, 60.0, 0.5);

    CHECK(tx.verifyTraceabilityFormula());
    CHECK(tx.validateInputReference());
    CHECK(tx.hasValidPrevReference());
    CHECK(tx.isTraceabilityValid());
}

// The central regression test. The old implementation substituted
// inputs[0].txHash for an unset prevTxHash and then compared the two, so the
// formula could not fail. A transaction with no declared ancestor sailed
// through the very check that exists to demand one.
GXC_TEST(Traceability, MissingAncestorIsRejected) {
    const std::string parent = Crypto::sha256("parent-tx");
    Transaction tx = traceableSpend(parent, 100.0, kRecipient, 60.0, 0.5);

    tx.setPrevTxHash("");
    CHECK_FALSE(tx.verifyTraceabilityFormula());
    CHECK_FALSE(tx.hasValidPrevReference());
    CHECK_FALSE(tx.isTraceabilityValid());

    tx.setPrevTxHash("0");
    CHECK_FALSE(tx.verifyTraceabilityFormula());
    CHECK_FALSE(tx.isTraceabilityValid());
}

GXC_TEST(Traceability, MismatchedAncestorIsRejected) {
    const std::string parent = Crypto::sha256("parent-tx");
    Transaction tx = traceableSpend(parent, 100.0, kRecipient, 60.0, 0.5);

    // Claim descent from a transaction other than the one actually spent.
    tx.setPrevTxHash(Crypto::sha256("some-other-tx"));
    CHECK_FALSE(tx.verifyTraceabilityFormula());
    CHECK_FALSE(tx.isTraceabilityValid());
}

GXC_TEST(Traceability, MismatchedReferencedAmountIsRejected) {
    const std::string parent = Crypto::sha256("parent-tx");
    Transaction tx = traceableSpend(parent, 100.0, kRecipient, 60.0, 0.5);

    // The declared inherited amount must equal what the input actually carries.
    tx.setReferencedAmount(0.0);
    CHECK_FALSE(tx.verifyTraceabilityFormula());

    tx.setReferencedAmount(999.0);
    CHECK_FALSE(tx.verifyTraceabilityFormula());

    tx.setReferencedAmount(100.0);
    CHECK(tx.verifyTraceabilityFormula());
}

GXC_TEST(Traceability, ReferencedAmountToleratesFloatingPointNoise) {
    const std::string parent = Crypto::sha256("parent-tx");
    Transaction tx = traceableSpend(parent, 100.0, kRecipient, 60.0, 0.5);

    // Sub-satoshi representation error must not break an honest transaction.
    tx.setReferencedAmount(100.0 + 1e-12);
    CHECK(tx.verifyTraceabilityFormula());

    // A full satoshi of discrepancy must still be caught.
    tx.setReferencedAmount(100.0 + 1e-7);
    CHECK_FALSE(tx.verifyTraceabilityFormula());
}

GXC_TEST(Traceability, NormalizeFillsInFieldsForThirdPartyWallets) {
    // A wallet that knows nothing about POT builds a transaction without the
    // fields, then calls normalizeTraceability() before signing.
    TransactionInput input;
    input.txHash = Crypto::sha256("funding-tx");
    input.outputIndex = 0;
    input.amount = 100.0;

    TransactionOutput output;
    output.address = kRecipient;
    output.amount = 99.5;

    Transaction tx({input}, {output}, "");
    tx.setFee(0.5);
    tx.setPrevTxHash("");
    tx.setReferencedAmount(0.0);

    CHECK_FALSE(tx.verifyTraceabilityFormula());

    tx.normalizeTraceability();

    CHECK_EQ(tx.getPrevTxHash(), input.txHash);
    CHECK_NEAR(tx.getReferencedAmount(), 100.0, 1e-9);
    CHECK(tx.verifyTraceabilityFormula());
}

GXC_TEST(Traceability, NormalizeDoesNotOverwriteDeclaredFields) {
    const std::string parent = Crypto::sha256("parent-tx");
    Transaction tx = traceableSpend(parent, 100.0, kRecipient, 60.0, 0.5);

    tx.normalizeTraceability();
    CHECK_EQ(tx.getPrevTxHash(), parent);
    CHECK_NEAR(tx.getReferencedAmount(), 100.0, 1e-9);
}

GXC_TEST(Traceability, InputsMustReferenceRealOutpoints) {
    TransactionInput empty;
    empty.txHash = "";
    empty.outputIndex = 0;
    empty.amount = 10.0;

    TransactionOutput output;
    output.address = kRecipient;
    output.amount = 10.0;

    Transaction tx({empty}, {output}, "");
    CHECK_FALSE(tx.validateInputReference());

    TransactionInput zeroAmount;
    zeroAmount.txHash = Crypto::sha256("real-tx");
    zeroAmount.outputIndex = 0;
    zeroAmount.amount = 0.0;

    Transaction zeroTx({zeroAmount}, {output}, zeroAmount.txHash);
    CHECK_FALSE(zeroTx.validateInputReference());
}

// Walking the chain of custody backwards is the whole point of POT: given any
// transaction, you can follow prevTxHash to its ancestor, repeatedly, until you
// reach the coinbase that minted the coins.
GXC_TEST(Traceability, ChainOfCustodyWalksBackToCoinbase) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();

    Transaction coinbase("GXCminer000000000000000000000000000", 50.0);
    const std::string coinbaseHash = coinbase.getHash();

    // Five hops, each spending the previous transaction in full minus a fee.
    std::vector<std::string> hashes;
    std::string parentHash = coinbaseHash;
    double amount = 50.0;

    for (int hop = 0; hop < 5; hop++) {
        const double fee = 0.01;
        Transaction tx = traceableSpend(parentHash, amount, kRecipient, amount - fee, fee);
        tx.signInputs(keys.privateKey);

        CHECK(tx.verifyTraceabilityFormula());
        CHECK(tx.verifyTransaction());

        hashes.push_back(tx.getHash());
        // The chain records where this hop came from.
        CHECK_EQ(tx.getPrevTxHash(), parentHash);

        parentHash = tx.getHash();
        amount = amount - fee;
    }

    CHECK_EQ(hashes.size(), size_t(5));
    // Every hop produced a distinct transaction id.
    for (size_t i = 1; i < hashes.size(); i++) {
        CHECK_NE(hashes[i], hashes[i - 1]);
    }
}

GXC_TEST(Traceability, BrokenLinkInTheMiddleIsDetected) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();

    Transaction first = traceableSpend(Crypto::sha256("origin"), 100.0, kRecipient, 99.0, 1.0);
    first.signInputs(keys.privateKey);
    CHECK(first.verifyTransaction());

    // The second hop claims descent from `first` but actually spends something
    // else -- laundering coins into the chain from outside it.
    TransactionInput forged;
    forged.txHash = Crypto::sha256("unrelated-utxo");
    forged.outputIndex = 0;
    forged.amount = 99.0;

    TransactionOutput output;
    output.address = kRecipient;
    output.amount = 98.0;

    Transaction second({forged}, {output}, first.getHash());
    second.setFee(1.0);
    second.setReferencedAmount(99.0);
    second.signInputs(keys.privateKey);

    // The declared ancestor and the actual input disagree: POT catches it.
    CHECK_FALSE(second.verifyTraceabilityFormula());
    CHECK_FALSE(second.isTraceabilityValid());
    CHECK_FALSE(second.verifyTransaction());
}

// ---------------------------------------------------------------------------
// Proof-of-Work Receipt
// ---------------------------------------------------------------------------

GXC_TEST(WorkReceipt, IsDeterministicForAGivenHeader) {
    Block block(1, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.setDifficulty(1.0);

    const std::string receipt = block.computeWorkReceipt();
    CHECK_EQ(receipt.size(), size_t(64));
    CHECK_EQ(receipt, block.computeWorkReceipt());
}

GXC_TEST(WorkReceipt, ChangesWithEveryCommittedField) {
    Block block(1, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.setDifficulty(1.0);

    const std::string base = block.computeWorkReceipt();

    // The nonce is what makes the receipt identify one specific solution.
    block.setNonce(block.getNonce() + 1);
    CHECK_NE(block.computeWorkReceipt(), base);
    block.setNonce(block.getNonce() - 1);
    CHECK_EQ(block.computeWorkReceipt(), base);

    // The miner identity.
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    CHECK_NE(block.computeWorkReceipt(), base);
}

GXC_TEST(WorkReceipt, CommitsToTheTransactionSet) {
    Block block(1, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.setDifficulty(1.0);
    block.calculateMerkleRoot();

    const std::string before = block.computeWorkReceipt();

    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    block.calculateMerkleRoot();

    // Because the receipt covers the merkle root, adding a transaction after the
    // fact invalidates it -- the receipt cannot be moved onto a different set of
    // transactions.
    CHECK_NE(block.computeWorkReceipt(), before);
}

GXC_TEST(WorkReceipt, MinedBlockCarriesAVerifiableReceipt) {
    Config::setNetworkMode(true); // testnet target: mineable on a CPU in the test

    Block block(1, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerAddress("GXCminer000000000000000000000000000");
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);

    Transaction coinbase("GXCminer000000000000000000000000000", 50.0);
    block.addTransactionUnchecked(coinbase);

    CHECK(block.mineBlock(1.0, 1000000));

    // Mining produced a receipt, and it is the one this header implies.
    CHECK_FALSE(block.getWorkReceiptHash().empty());
    CHECK_EQ(block.getWorkReceiptHash(), block.computeWorkReceipt());
    CHECK(block.verifyWorkReceipt());
}

// The receipt is what makes a mining reward auditable: the coinbase must carry
// the same receipt as the block and the block's own height, so a newly minted
// coin can always be traced to the work that minted it.
GXC_TEST(WorkReceipt, CoinbaseIsBoundToTheBlockThatMintedIt) {
    Config::setNetworkMode(true);

    Block block(7, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerAddress("GXCminer000000000000000000000000000");
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));

    CHECK(block.mineBlock(1.0, 1000000));

    const auto& transactions = block.getTransactions();
    CHECK_EQ(transactions.size(), size_t(1));
    CHECK(transactions[0].isCoinbaseTransaction());

    // Mining stamped the coinbase with the receipt and the height.
    CHECK_EQ(transactions[0].getWorkReceiptHash(), block.getWorkReceiptHash());
    CHECK_EQ(transactions[0].getBlockHeight(), uint32_t(7));
    CHECK(block.verifyWorkReceipt());
}

GXC_TEST(WorkReceipt, MissingReceiptIsRejected) {
    Block block(1, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.setDifficulty(1.0);

    // A PoW block with no receipt at all cannot be accepted.
    CHECK_FALSE(block.verifyWorkReceipt());
}

GXC_TEST(WorkReceipt, ForgedReceiptIsRejected) {
    Config::setNetworkMode(true);

    Block block(1, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    CHECK(block.mineBlock(1.0, 1000000));
    CHECK(block.verifyWorkReceipt());

    // Substituting an invented receipt must fail: it is not what the header implies.
    block.setWorkReceiptHash(Crypto::sha256("invented-receipt"));
    CHECK_FALSE(block.verifyWorkReceipt());
}

GXC_TEST(WorkReceipt, ReceiptFromAnotherBlockIsRejected) {
    Config::setNetworkMode(true);

    Block first(1, Crypto::sha256("previous-a"), BlockType::POW_SHA256);
    first.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    first.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    CHECK(first.mineBlock(1.0, 1000000));

    Block second(2, Crypto::sha256("previous-b"), BlockType::POW_SHA256);
    second.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    second.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    CHECK(second.mineBlock(1.0, 1000000));

    CHECK_NE(first.getWorkReceiptHash(), second.getWorkReceiptHash());

    // Transplanting a valid receipt from one block onto another must fail.
    second.setWorkReceiptHash(first.getWorkReceiptHash());
    CHECK_FALSE(second.verifyWorkReceipt());
}

GXC_TEST(WorkReceipt, CoinbaseWithWrongHeightIsRejected) {
    Config::setNetworkMode(true);

    Block block(9, Crypto::sha256("previous"), BlockType::POW_SHA256);
    block.setMinerPublicKey(Crypto::generateKeyPair().publicKey);
    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    CHECK(block.mineBlock(1.0, 1000000));
    CHECK(block.verifyWorkReceipt());

    // Rebuild the block with a coinbase claiming the wrong height.
    Block tampered = block;
    Transaction coinbase = block.getTransactions()[0];
    coinbase.setBlockHeight(999);

    Block rebuilt(9, block.getPreviousHash(), BlockType::POW_SHA256);
    rebuilt.setMinerPublicKey(block.getMinerPublicKey());
    rebuilt.setNonce(block.getNonce());
    rebuilt.setTimestamp(block.getTimestamp());
    rebuilt.setDifficulty(block.getDifficulty());
    rebuilt.addTransactionUnchecked(coinbase);
    rebuilt.setMerkleRoot(block.getMerkleRoot());
    rebuilt.setWorkReceiptHash(block.getWorkReceiptHash());

    CHECK_FALSE(rebuilt.verifyWorkReceipt());
}

GXC_TEST(WorkReceipt, ProofOfStakeBlocksCarryNoReceipt) {
    Block block(1, Crypto::sha256("previous"), BlockType::POS);
    block.setValidatorAddress("GXCvalidator00000000000000000000000");

    // PoS blocks mint no mining reward, so there is nothing to receipt.
    CHECK(block.verifyWorkReceipt());

    block.setWorkReceiptHash(Crypto::sha256("bogus"));
    CHECK_FALSE(block.verifyWorkReceipt());
}

// ---------------------------------------------------------------------------
// The two mechanisms together
// ---------------------------------------------------------------------------

GXC_TEST(Traceability, MintedCoinsAreTraceableFromSpendToWork) {
    Config::setNetworkMode(true);
    const Crypto::KeyPair miner = Crypto::generateKeyPair();

    // 1. Mine a block. The coinbase is stamped with the work receipt.
    Block block(1, Crypto::sha256("genesis"), BlockType::POW_SHA256);
    block.setMinerAddress("GXCminer000000000000000000000000000");
    block.setMinerPublicKey(miner.publicKey);
    block.addTransactionUnchecked(Transaction("GXCminer000000000000000000000000000", 50.0));
    CHECK(block.mineBlock(1.0, 1000000));
    CHECK(block.verifyWorkReceipt());

    const Transaction& coinbase = block.getTransactions()[0];
    const std::string receipt = coinbase.getWorkReceiptHash();

    // 2. Spend the reward. POT records the coinbase as the ancestor.
    Transaction spend = traceableSpend(coinbase.getHash(), 50.0, kRecipient, 49.0, 1.0);
    spend.signInputs(miner.privateKey);
    CHECK(spend.verifyTransaction());

    // 3. From the spend, the ancestor is the coinbase...
    CHECK_EQ(spend.getPrevTxHash(), coinbase.getHash());
    // ...and from the coinbase, the receipt names the work that minted it...
    CHECK_EQ(receipt, block.computeWorkReceipt());
    // ...which is bound to this block's height and this block's transactions.
    CHECK_EQ(coinbase.getBlockHeight(), block.getIndex());
    CHECK(meetsTarget(block.getHash(), block.getDifficulty(), true));
}
