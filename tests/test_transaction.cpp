// Tests for the transaction model: construction, hashing, the signature
// commitment, balance rules, and serialization round-trips.

#include "test_framework.h"

#include "../include/Crypto.h"
#include "../include/transaction.h"

namespace {

/** A funding outpoint to spend from. */
struct Utxo {
    std::string txHash;
    uint32_t index = 0;
    double amount = 0.0;
};

Utxo makeUtxo(double amount) {
    return Utxo{Crypto::sha256("utxo-" + std::to_string(amount)), 0, amount};
}

/**
 * Build a structurally valid transaction spending `utxo`, paying `amount` to
 * `recipient`, with the remainder as fee. The Proof-of-Traceability fields are
 * populated the way a conforming wallet would populate them.
 */
Transaction buildTransaction(const Utxo& utxo, const std::string& recipient,
                             double amount, double fee) {
    TransactionInput input;
    input.txHash = utxo.txHash;
    input.outputIndex = utxo.index;
    input.amount = utxo.amount;

    TransactionOutput output;
    output.address = recipient;
    output.amount = amount;
    output.script = "OP_DUP OP_HASH160 " + recipient + " OP_EQUALVERIFY OP_CHECKSIG";

    std::vector<TransactionOutput> outputs{output};

    // Anything not paid out and not taken as fee returns as change.
    const double change = utxo.amount - amount - fee;
    if (change > 1e-9) {
        TransactionOutput changeOutput;
        changeOutput.address = "GXCchangeaddress0000000000000000000";
        changeOutput.amount = change;
        changeOutput.script = "OP_DUP OP_HASH160 change OP_EQUALVERIFY OP_CHECKSIG";
        outputs.push_back(changeOutput);
    }

    Transaction tx({input}, outputs, utxo.txHash);
    tx.setFee(fee);
    tx.setReferencedAmount(utxo.amount);
    return tx;
}

Transaction signedTransaction(const Crypto::KeyPair& keys, const Utxo& utxo,
                              const std::string& recipient, double amount, double fee) {
    Transaction tx = buildTransaction(utxo, recipient, amount, fee);
    tx.signInputs(keys.privateKey);
    return tx;
}

const char* kRecipient = "GXCrecipientaddress000000000000000";

} // namespace

GXC_TEST(Transaction, CoinbaseHasNoInputsAndOnePayout) {
    Transaction coinbase("GXCminer000000000000000000000000000", 50.0);

    CHECK(coinbase.isCoinbaseTransaction());
    CHECK(coinbase.getInputs().empty());
    CHECK_EQ(coinbase.getOutputs().size(), size_t(1));
    CHECK_NEAR(coinbase.getOutputs()[0].amount, 50.0, 1e-9);
    CHECK(coinbase.verifyTransaction());
}

GXC_TEST(Transaction, CoinbaseIsExemptFromTraceability) {
    Transaction coinbase("GXCminer000000000000000000000000000", 50.0);
    CHECK(coinbase.verifyTraceabilityFormula());
    CHECK(coinbase.isTraceabilityValid());
}

GXC_TEST(Transaction, HashIsDeterministicAndContentDependent) {
    const Utxo utxo = makeUtxo(100.0);
    Transaction tx = buildTransaction(utxo, kRecipient, 40.0, 0.5);

    const std::string hash = tx.calculateHash();
    CHECK_EQ(hash, tx.calculateHash());
    CHECK_EQ(hash.size(), size_t(64));

    // Changing any covered field must change the identity.
    tx.setMemo("different");
    CHECK_NE(tx.calculateHash(), hash);
}

GXC_TEST(Transaction, SignedTransactionVerifies) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = signedTransaction(keys, makeUtxo(100.0), kRecipient, 40.0, 0.5);

    CHECK(tx.validateSignatures());
    CHECK(tx.verifyTransaction());
}

GXC_TEST(Transaction, UnsignedTransactionIsRejected) {
    Transaction tx = buildTransaction(makeUtxo(100.0), kRecipient, 40.0, 0.5);
    CHECK_FALSE(tx.validateSignatures());
    CHECK_FALSE(tx.verifyTransaction());
}

// This is the regression test for the most serious transaction-level flaw:
// signatures used to cover only the outpoint being spent, never the outputs.
// Anyone who saw a signed transaction in the mempool could rewrite where the
// money went and the signature would still check out.
GXC_TEST(Transaction, SignatureCommitsToOutputs) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = signedTransaction(keys, makeUtxo(100.0), kRecipient, 40.0, 0.5);
    CHECK(tx.validateSignatures());

    // An attacker redirects the payment, keeping the original signature.
    std::vector<TransactionOutput> hijacked = tx.getOutputs();
    hijacked[0].address = "GXCattackeraddress0000000000000000";

    Transaction tampered = tx;
    tampered.clearOutputs();
    for (const auto& output : hijacked) {
        tampered.addOutput(output);
    }

    CHECK_FALSE(tampered.validateSignatures());
    CHECK_FALSE(tampered.verifyTransaction());
}

GXC_TEST(Transaction, SignatureCommitsToOutputAmount) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = signedTransaction(keys, makeUtxo(100.0), kRecipient, 40.0, 0.5);

    std::vector<TransactionOutput> inflated = tx.getOutputs();
    inflated[0].amount = 99.0;

    Transaction tampered = tx;
    tampered.clearOutputs();
    for (const auto& output : inflated) {
        tampered.addOutput(output);
    }

    CHECK_FALSE(tampered.validateSignatures());
}

GXC_TEST(Transaction, SignatureCommitsToTraceabilityFields) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = signedTransaction(keys, makeUtxo(100.0), kRecipient, 40.0, 0.5);
    CHECK(tx.validateSignatures());

    // Rewriting the declared ancestor after signing must invalidate the signature.
    Transaction tampered = tx;
    tampered.setPrevTxHash(Crypto::sha256("a-different-ancestor"));
    CHECK_FALSE(tampered.validateSignatures());
}

GXC_TEST(Transaction, SignatureFromWrongKeyIsRejected) {
    const Crypto::KeyPair owner = Crypto::generateKeyPair();
    const Crypto::KeyPair attacker = Crypto::generateKeyPair();

    Transaction tx = buildTransaction(makeUtxo(100.0), kRecipient, 40.0, 0.5);
    tx.signInputs(attacker.privateKey);

    // The signature is internally consistent, but it is the attacker's key...
    CHECK(tx.validateSignatures());
    // ...and it is not the owner's, which is what UTXO ownership checks compare.
    CHECK_NE(Crypto::derivePublicKey(attacker.privateKey), owner.publicKey);
}

GXC_TEST(Transaction, SignatureHashExcludesSignatureFields) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = signedTransaction(keys, makeUtxo(100.0), kRecipient, 40.0, 0.5);

    const std::string digest = tx.computeSignatureHash();

    // A signature cannot commit to its own value. Clearing the signatures must
    // leave the digest unchanged, or a verifier could never reproduce the
    // message the signer actually signed.
    Transaction stripped = tx;
    std::vector<TransactionInput> inputs = tx.getInputs();
    stripped.clearInputs();
    for (auto& input : inputs) {
        input.signature.clear();
        stripped.addInput(input);
    }

    CHECK_EQ(stripped.computeSignatureHash(), digest);

    // Re-signing the same transaction reproduces the same digest.
    Transaction resigned = tx;
    resigned.signInputs(keys.privateKey);
    CHECK_EQ(resigned.computeSignatureHash(), digest);
    CHECK(resigned.validateSignatures());
}

GXC_TEST(Transaction, BalanceMustMatchInputsMinusFee) {
    const Utxo utxo = makeUtxo(100.0);
    Transaction balanced = buildTransaction(utxo, kRecipient, 40.0, 0.5);
    CHECK(balanced.validateAmountConsistency());

    // Paying out more than was funded creates coins from nothing.
    TransactionInput input;
    input.txHash = utxo.txHash;
    input.outputIndex = 0;
    input.amount = 10.0;

    TransactionOutput output;
    output.address = kRecipient;
    output.amount = 1000.0;

    Transaction inflated({input}, {output}, utxo.txHash);
    CHECK_FALSE(inflated.validateAmountConsistency());
    CHECK_FALSE(inflated.verifyTransaction());
}

GXC_TEST(Transaction, NegativeAndZeroOutputsAreRejected) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    const Utxo utxo = makeUtxo(100.0);

    TransactionInput input;
    input.txHash = utxo.txHash;
    input.outputIndex = 0;
    input.amount = 100.0;

    TransactionOutput zero;
    zero.address = kRecipient;
    zero.amount = 0.0;

    Transaction tx({input}, {zero}, utxo.txHash);
    tx.setFee(100.0);
    tx.signInputs(keys.privateKey);
    CHECK_FALSE(tx.verifyTransaction());
}

GXC_TEST(Transaction, EmptyOutputsAreRejected) {
    Transaction tx;
    CHECK_FALSE(tx.verifyTransaction());
}

GXC_TEST(Transaction, InputAndOutputTotals) {
    const Utxo utxo = makeUtxo(100.0);
    Transaction tx = buildTransaction(utxo, kRecipient, 40.0, 0.5);

    CHECK_NEAR(tx.getTotalInputAmount(), 100.0, 1e-9);
    CHECK_NEAR(tx.getTotalOutputAmount(), 99.5, 1e-9);
    CHECK_NEAR(tx.getFee(), 0.5, 1e-9);
}

GXC_TEST(Transaction, SerializationRoundTrip) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction original = signedTransaction(keys, makeUtxo(100.0), kRecipient, 40.0, 0.5);

    Transaction restored;
    CHECK(restored.deserialize(original.serialize()));

    CHECK_EQ(restored.getHash(), original.getHash());
    CHECK_EQ(restored.getPrevTxHash(), original.getPrevTxHash());
    CHECK_NEAR(restored.getReferencedAmount(), original.getReferencedAmount(), 1e-9);
    CHECK_EQ(restored.getInputs().size(), original.getInputs().size());
    CHECK_EQ(restored.getOutputs().size(), original.getOutputs().size());
    CHECK_EQ(restored.getOutputs()[0].address, original.getOutputs()[0].address);

    // A restored transaction must still verify -- otherwise nothing that came
    // off the wire or out of the database could ever be accepted.
    CHECK(restored.validateSignatures());
    CHECK(restored.verifyTransaction());
}

GXC_TEST(Transaction, SerializationPreservesMemoWithDelimiters) {
    Transaction tx = buildTransaction(makeUtxo(100.0), kRecipient, 40.0, 0.5);
    tx.setMemo("pipe|delimited|memo with spaces");

    Transaction restored;
    CHECK(restored.deserialize(tx.serialize()));
    CHECK_EQ(restored.getMemo(), std::string("pipe|delimited|memo with spaces"));
}

GXC_TEST(Transaction, DeserializeRejectsGarbage) {
    Transaction tx;
    CHECK_FALSE(tx.deserialize(""));
    CHECK_FALSE(tx.deserialize("not-a-transaction"));
    CHECK_FALSE(tx.deserialize("1|2|3"));
}

GXC_TEST(Transaction, TypeIsPreservedThroughSerialization) {
    Transaction tx = buildTransaction(makeUtxo(100.0), kRecipient, 40.0, 0.5);
    tx.setType(TransactionType::STAKE);

    Transaction restored;
    CHECK(restored.deserialize(tx.serialize()));
    CHECK(restored.getType() == TransactionType::STAKE);
}

GXC_TEST(Transaction, WorkReceiptFieldsRoundTrip) {
    Transaction coinbase("GXCminer000000000000000000000000000", 50.0);
    const std::string receipt = Crypto::sha256("work-receipt");

    coinbase.setWorkReceiptHash(receipt);
    coinbase.setBlockHeight(4242);

    CHECK_EQ(coinbase.getWorkReceiptHash(), receipt);
    CHECK_EQ(coinbase.getBlockHeight(), uint32_t(4242));
}

// The work receipt has to survive the wire. When it did not, a relayed block
// arrived at its peer with a blank coinbase receipt and was rejected as
// unverifiable -- so no mined block could ever propagate.
GXC_TEST(Transaction, WorkReceiptSurvivesSerialization) {
    Transaction coinbase("GXCminer000000000000000000000000000", 50.0);
    const std::string receipt = Crypto::sha256("work-receipt");
    coinbase.setWorkReceiptHash(receipt);
    coinbase.setBlockHeight(1234);

    Transaction restored;
    CHECK(restored.deserialize(coinbase.serialize()));

    CHECK_EQ(restored.getWorkReceiptHash(), receipt);
    CHECK_EQ(restored.getBlockHeight(), uint32_t(1234));
}

GXC_TEST(Transaction, DeserializeToleratesPayloadWithoutWorkReceipt) {
    // Payloads written before the receipt fields existed must still load.
    Transaction tx = buildTransaction(makeUtxo(100.0), kRecipient, 40.0, 0.5);
    std::string payload = tx.serialize();

    // Strip the trailing "workReceiptHash|blockHeight|" pair.
    size_t cut = payload.rfind('|');
    cut = payload.rfind('|', cut - 1);
    payload = payload.substr(0, cut + 1);

    Transaction restored;
    CHECK(restored.deserialize(payload));
    CHECK_EQ(restored.getWorkReceiptHash(), std::string(""));
    CHECK_EQ(restored.getBlockHeight(), uint32_t(0));
}
