// Sending value: the full payment path from a funded output to a spend that a
// node will accept, and the ways an invalid spend has to fail.
//
// These exercise the transaction layer directly rather than through Blockchain,
// which needs a LevelDB instance. What is covered here is everything that
// determines whether a payment is well-formed: UTXO selection arithmetic,
// change, fees, authorization, multi-input and multi-output spends, and the
// chained sends that Proof of Traceability threads together.

#include "test_framework.h"

#include "../include/Crypto.h"
#include "../include/transaction.h"

#include <map>

namespace {

/** A spendable output belonging to `owner`. */
struct Utxo {
    std::string txHash;
    uint32_t index;
    double amount;
};

Utxo fund(const std::string& tag, double amount, uint32_t index = 0) {
    return Utxo{Crypto::sha256("funding-" + tag), index, amount};
}

TransactionInput toInput(const Utxo& utxo) {
    TransactionInput input;
    input.txHash = utxo.txHash;
    input.outputIndex = utxo.index;
    input.amount = utxo.amount;
    return input;
}

TransactionOutput payTo(const std::string& address, double amount) {
    TransactionOutput output;
    output.address = address;
    output.amount = amount;
    output.script = "OP_DUP OP_HASH160 " + address + " OP_EQUALVERIFY OP_CHECKSIG";
    return output;
}

/**
 * Build and sign a payment of `amount` to `to`, funded by `utxos`, paying
 * `fee`, with any remainder returned to `changeAddress`.
 */
Transaction send(const Crypto::KeyPair& sender,
                 const std::vector<Utxo>& utxos,
                 const std::string& to,
                 double amount,
                 double fee,
                 const std::string& changeAddress) {
    std::vector<TransactionInput> inputs;
    double funded = 0.0;
    for (const auto& utxo : utxos) {
        inputs.push_back(toInput(utxo));
        funded += utxo.amount;
    }

    std::vector<TransactionOutput> outputs{payTo(to, amount)};

    const double change = funded - amount - fee;
    if (change > 1e-9) {
        outputs.push_back(payTo(changeAddress, change));
    }

    Transaction tx(inputs, outputs, utxos.front().txHash);
    tx.setFee(fee);
    tx.setReferencedAmount(utxos.front().amount);
    tx.setSenderAddress(Crypto::generateAddress(sender.publicKey, true));
    tx.setReceiverAddress(to);
    tx.signInputs(sender.privateKey);
    return tx;
}

const char* kRecipient = "GXCrecipient0000000000000000000000";
const char* kChange = "GXCchange00000000000000000000000000";

} // namespace

// ---------------------------------------------------------------------------
// The basic payment
// ---------------------------------------------------------------------------

GXC_TEST(Sending, SimplePaymentIsValid) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction tx = send(alice, {fund("a", 100.0)}, kRecipient, 40.0, 0.5, kChange);

    CHECK(tx.verifyTransaction());
    CHECK(tx.validateSignatures());
    CHECK(tx.isTraceabilityValid());
}

GXC_TEST(Sending, ChangeIsReturnedToTheSender) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction tx = send(alice, {fund("b", 100.0)}, kRecipient, 40.0, 0.5, kChange);

    CHECK_EQ(tx.getOutputs().size(), size_t(2));
    CHECK_EQ(tx.getOutputs()[0].address, std::string(kRecipient));
    CHECK_NEAR(tx.getOutputs()[0].amount, 40.0, 1e-9);
    CHECK_EQ(tx.getOutputs()[1].address, std::string(kChange));
    CHECK_NEAR(tx.getOutputs()[1].amount, 59.5, 1e-9);
}

GXC_TEST(Sending, ExactSpendProducesNoChangeOutput) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    // 100 in, 99.9 out, 0.1 fee: nothing left over.
    Transaction tx = send(alice, {fund("c", 100.0)}, kRecipient, 99.9, 0.1, kChange);

    CHECK_EQ(tx.getOutputs().size(), size_t(1));
    CHECK(tx.verifyTransaction());
}

GXC_TEST(Sending, ValueIsConserved) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction tx = send(alice, {fund("d", 100.0)}, kRecipient, 40.0, 0.5, kChange);

    // inputs == outputs + fee, exactly. No value created, none destroyed.
    CHECK_NEAR(tx.getTotalInputAmount(),
               tx.getTotalOutputAmount() + tx.getFee(), 1e-9);
    CHECK(tx.validateAmountConsistency());
}

GXC_TEST(Sending, FeeIsWhatIsLeftUnclaimed) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction tx = send(alice, {fund("e", 100.0)}, kRecipient, 40.0, 2.5, kChange);

    CHECK_NEAR(tx.getFee(), 2.5, 1e-9);
    CHECK_NEAR(tx.getTotalInputAmount() - tx.getTotalOutputAmount(), 2.5, 1e-9);
}

// ---------------------------------------------------------------------------
// Multiple inputs and outputs
// ---------------------------------------------------------------------------

GXC_TEST(Sending, MultipleInputsAreCombined) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    const std::vector<Utxo> utxos{
        fund("m1", 30.0, 0), fund("m2", 45.0, 1), fund("m3", 25.0, 2)};

    Transaction tx = send(alice, utxos, kRecipient, 95.0, 1.0, kChange);

    CHECK_EQ(tx.getInputs().size(), size_t(3));
    CHECK_NEAR(tx.getTotalInputAmount(), 100.0, 1e-9);
    CHECK(tx.verifyTransaction());
}

GXC_TEST(Sending, EveryInputIsSignedIndependently) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction tx = send(alice, {fund("n1", 50.0, 0), fund("n2", 50.0, 1)},
                          kRecipient, 95.0, 1.0, kChange);

    for (const auto& input : tx.getInputs()) {
        CHECK_FALSE(input.signature.empty());
        CHECK_EQ(input.publicKey, alice.publicKey);
    }
    CHECK(tx.validateSignatures());
}

GXC_TEST(Sending, PaymentToManyRecipients) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    const Utxo utxo = fund("o", 100.0);

    std::vector<TransactionOutput> outputs{
        payTo("GXCrecipient1000000000000000000000", 30.0),
        payTo("GXCrecipient2000000000000000000000", 25.0),
        payTo("GXCrecipient3000000000000000000000", 44.5),
    };

    Transaction tx({toInput(utxo)}, outputs, utxo.txHash);
    tx.setFee(0.5);
    tx.setReferencedAmount(utxo.amount);
    tx.signInputs(alice.privateKey);

    CHECK_EQ(tx.getOutputs().size(), size_t(3));
    CHECK(tx.verifyTransaction());
}

// ---------------------------------------------------------------------------
// Invalid sends
// ---------------------------------------------------------------------------

GXC_TEST(Sending, OverspendingIsRejected) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    const Utxo utxo = fund("p", 10.0);

    // Claim 10 GXC of input, pay out 1000.
    Transaction tx({toInput(utxo)}, {payTo(kRecipient, 1000.0)}, utxo.txHash);
    tx.setReferencedAmount(utxo.amount);
    tx.signInputs(alice.privateKey);

    CHECK_FALSE(tx.validateAmountConsistency());
    CHECK_FALSE(tx.verifyTransaction());
}

GXC_TEST(Sending, PayingLessThanTheInputsWithoutDeclaringAFeeIsRejected) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    const Utxo utxo = fund("q", 100.0);

    // 100 in, 40 out, fee left at zero: 60 GXC is unaccounted for.
    Transaction tx({toInput(utxo)}, {payTo(kRecipient, 40.0)}, utxo.txHash);
    tx.setReferencedAmount(utxo.amount);
    tx.signInputs(alice.privateKey);

    CHECK_FALSE(tx.verifyTransaction());
}

GXC_TEST(Sending, NegativeOutputIsRejected) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    const Utxo utxo = fund("r", 100.0);

    Transaction tx({toInput(utxo)},
                   {payTo(kRecipient, 150.0), payTo(kChange, -50.0)}, utxo.txHash);
    tx.setReferencedAmount(utxo.amount);
    tx.signInputs(alice.privateKey);

    CHECK_FALSE(tx.verifyTransaction());
}

GXC_TEST(Sending, UnsignedPaymentIsRejected) {
    const Utxo utxo = fund("s", 100.0);

    Transaction tx({toInput(utxo)}, {payTo(kRecipient, 99.5)}, utxo.txHash);
    tx.setFee(0.5);
    tx.setReferencedAmount(utxo.amount);
    // Never signed.

    CHECK_FALSE(tx.validateSignatures());
    CHECK_FALSE(tx.verifyTransaction());
}

GXC_TEST(Sending, RedirectingASignedPaymentBreaksIt) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction tx = send(alice, {fund("t", 100.0)}, kRecipient, 40.0, 0.5, kChange);
    CHECK(tx.verifyTransaction());

    // An attacker intercepts the signed payment and swaps the recipient.
    std::vector<TransactionOutput> hijacked = tx.getOutputs();
    hijacked[0].address = "GXCattacker00000000000000000000000";

    Transaction stolen = tx;
    stolen.clearOutputs();
    for (const auto& output : hijacked) {
        stolen.addOutput(output);
    }

    CHECK_FALSE(stolen.validateSignatures());
    CHECK_FALSE(stolen.verifyTransaction());
}

GXC_TEST(Sending, SpendWithNoInputsIsRejected) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();

    Transaction tx({}, {payTo(kRecipient, 50.0)}, Crypto::sha256("nothing"));
    tx.signInputs(alice.privateKey);

    // Only a coinbase may create outputs without inputs.
    CHECK_FALSE(tx.verifyTransaction());
}

// ---------------------------------------------------------------------------
// Chained sends
// ---------------------------------------------------------------------------

GXC_TEST(Sending, PaymentChainStaysTraceable) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    const Crypto::KeyPair bob = Crypto::generateKeyPair();
    const Crypto::KeyPair carol = Crypto::generateKeyPair();

    // Alice pays Bob.
    Transaction first = send(alice, {fund("chain", 100.0)},
                             Crypto::generateAddress(bob.publicKey, true),
                             99.0, 1.0, kChange);
    CHECK(first.verifyTransaction());

    // Bob spends what he received, which is output 0 of Alice's payment.
    const Utxo fromAlice{first.getHash(), 0, 99.0};
    Transaction second = send(bob, {fromAlice},
                              Crypto::generateAddress(carol.publicKey, true),
                              98.0, 1.0, kChange);
    CHECK(second.verifyTransaction());

    // The chain of custody is explicit and checkable at every hop.
    CHECK_EQ(second.getPrevTxHash(), first.getHash());
    CHECK_NEAR(second.getReferencedAmount(), 99.0, 1e-9);
    CHECK(second.verifyTraceabilityFormula());
}

GXC_TEST(Sending, ValueDecreasesByExactlyTheFeesAlongAChain) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();

    double amount = 100.0;
    std::string parent = Crypto::sha256("chain-origin");
    const double fee = 0.25;

    for (int hop = 0; hop < 6; hop++) {
        const Utxo utxo{parent, 0, amount};
        Transaction tx = send(keys, {utxo}, kRecipient, amount - fee, fee, kChange);

        CHECK(tx.verifyTransaction());
        CHECK_NEAR(tx.getTotalOutputAmount(), amount - fee, 1e-9);

        parent = tx.getHash();
        amount -= fee;
    }

    CHECK_NEAR(amount, 100.0 - 6 * fee, 1e-9);
}

GXC_TEST(Sending, SpendsSurviveSerializationIntact) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction original = send(alice, {fund("u1", 60.0, 0), fund("u2", 40.0, 1)},
                                kRecipient, 95.0, 1.0, kChange);

    Transaction restored;
    CHECK(restored.deserialize(original.serialize()));

    CHECK_EQ(restored.getHash(), original.getHash());
    CHECK_EQ(restored.getInputs().size(), size_t(2));
    CHECK_EQ(restored.getOutputs().size(), original.getOutputs().size());
    CHECK_NEAR(restored.getTotalOutputAmount(), original.getTotalOutputAmount(), 1e-9);

    // A payment relayed to a peer must still be spendable there.
    CHECK(restored.verifyTransaction());
}

// ---------------------------------------------------------------------------
// Typed sends
// ---------------------------------------------------------------------------

GXC_TEST(Sending, StakeAndUnstakeTransactionsCarryTheirType) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();

    for (TransactionType type : {TransactionType::STAKE, TransactionType::UNSTAKE,
                                 TransactionType::REVERSAL}) {
        Transaction tx = send(alice, {fund("typed", 500.0)}, kRecipient, 499.0, 1.0, kChange);
        tx.setType(type);
        tx.signInputs(alice.privateKey);   // type is inside the signed digest

        CHECK(tx.getType() == type);
        CHECK(tx.validateSignatures());

        Transaction restored;
        CHECK(restored.deserialize(tx.serialize()));
        CHECK(restored.getType() == type);
    }
}

GXC_TEST(Sending, ChangingTypeAfterSigningInvalidatesTheSignature) {
    const Crypto::KeyPair alice = Crypto::generateKeyPair();
    Transaction tx = send(alice, {fund("v", 500.0)}, kRecipient, 499.0, 1.0, kChange);
    CHECK(tx.validateSignatures());

    // A relayer must not be able to reclassify a payment as a stake withdrawal.
    tx.setType(TransactionType::UNSTAKE);
    CHECK_FALSE(tx.validateSignatures());
}

GXC_TEST(Sending, MiningRewardIsSpendable) {
    const Crypto::KeyPair miner = Crypto::generateKeyPair();
    const std::string minerAddress = Crypto::generateAddress(miner.publicKey, true);

    Transaction coinbase(minerAddress, 50.0);
    CHECK(coinbase.verifyTransaction());

    // The reward becomes an ordinary output, spendable like any other.
    const Utxo reward{coinbase.getHash(), 0, 50.0};
    Transaction spend = send(miner, {reward}, kRecipient, 49.5, 0.5, kChange);

    CHECK(spend.verifyTransaction());
    CHECK_EQ(spend.getPrevTxHash(), coinbase.getHash());
}
