// The signature-scheme abstraction.
//
// Every input declares which scheme authorises it. The point is migration:
// secp256k1 falls to Shor's algorithm, so a post-quantum scheme will be needed
// eventually, and introducing one is a soft fork only if the field is already
// there and already covered by the signature hash.
//
// The properties that matter are all about failing closed. An input must not be
// able to name a scheme nothing implements and slip through unverified, and it
// must not be possible to change the declared scheme after signing.

#include "test_framework.h"

#include "../include/Crypto.h"
#include "../include/transaction.h"

#include <string>
#include <vector>

namespace {

const char* kRecipient = "GXCrecipient0000000000000000000000";

Transaction buildSpend() {
    TransactionInput input;
    input.txHash = Crypto::sha256("scheme-funding");
    input.outputIndex = 0;
    input.amount = 100.0;

    TransactionOutput output;
    output.address = kRecipient;
    output.amount = 99.5;

    Transaction tx({input}, {output}, input.txHash);
    tx.setFee(0.5);
    tx.setReferencedAmount(100.0);
    return tx;
}

/** Rebuild `tx` with `inputs` substituted, as a relayer repackaging it would. */
Transaction withInputs(const Transaction& tx, const std::vector<TransactionInput>& inputs) {
    Transaction copy = tx;
    copy.clearInputs();
    for (const auto& input : inputs) {
        copy.addInput(input);
    }
    return copy;
}

} // namespace

GXC_TEST(SignatureScheme, ClassicalIsTheDefault) {
    Transaction tx = buildSpend();
    CHECK(tx.getInputs()[0].scheme == SignatureScheme::ECDSA_SECP256K1);
}

GXC_TEST(SignatureScheme, OnlyTheClassicalSchemeIsImplemented) {
    CHECK(isSupportedSignatureScheme(SignatureScheme::ECDSA_SECP256K1));

    // Reserved identifiers must report as unsupported until something actually
    // implements them.
    CHECK_FALSE(isSupportedSignatureScheme(SignatureScheme::ML_DSA_44));
    CHECK_FALSE(isSupportedSignatureScheme(SignatureScheme::FN_DSA_512));
    CHECK_FALSE(isSupportedSignatureScheme(SignatureScheme::HYBRID_ECDSA_ML_DSA_44));
}

GXC_TEST(SignatureScheme, NamesAreStable) {
    CHECK_EQ(std::string(signatureSchemeName(SignatureScheme::ECDSA_SECP256K1)),
             std::string("ecdsa-secp256k1"));
    CHECK_EQ(std::string(signatureSchemeName(SignatureScheme::ML_DSA_44)),
             std::string("ml-dsa-44"));
    CHECK_EQ(std::string(signatureSchemeName(SignatureScheme::FN_DSA_512)),
             std::string("fn-dsa-512"));
}

GXC_TEST(SignatureScheme, SigningStampsTheSchemeOnEveryInput) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();

    CHECK(tx.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));

    for (const auto& input : tx.getInputs()) {
        CHECK(input.scheme == SignatureScheme::ECDSA_SECP256K1);
        CHECK_FALSE(input.signature.empty());
    }
    CHECK(tx.validateSignatures());
}

GXC_TEST(SignatureScheme, SigningUnderAnUnimplementedSchemeFailsClosed) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();

    // Must refuse rather than silently fall back to the classical scheme.
    CHECK_FALSE(tx.signInputs(keys.privateKey, SignatureScheme::ML_DSA_44));
    CHECK_FALSE(tx.validateSignatures());
}

// The load-bearing case. If an unimplemented scheme were merely skipped rather
// than rejected, an attacker could authorise any transaction by declaring a
// scheme nobody verifies.
GXC_TEST(SignatureScheme, InputDeclaringAnUnsupportedSchemeIsRejected) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();
    CHECK(tx.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));
    CHECK(tx.validateSignatures());

    // Re-declare the (valid) signature as belonging to a scheme this build
    // cannot verify.
    std::vector<TransactionInput> tampered = tx.getInputs();
    tampered[0].scheme = SignatureScheme::ML_DSA_44;

    const Transaction forged = withInputs(tx, tampered);
    CHECK_FALSE(forged.validateSignatures());
    CHECK_FALSE(forged.verifyTransaction());
}

GXC_TEST(SignatureScheme, SignatureCommitsToTheDeclaredScheme) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();
    CHECK(tx.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));

    const std::string digest = tx.computeSignatureHash();

    // Changing the scheme must change the signed message, so an input cannot be
    // downgraded to a weaker scheme while keeping its signature.
    std::vector<TransactionInput> altered = tx.getInputs();
    altered[0].scheme = SignatureScheme::FN_DSA_512;

    CHECK_NE(withInputs(tx, altered).computeSignatureHash(), digest);
}

GXC_TEST(SignatureScheme, SchemeIsPartOfTheTransactionId) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();
    CHECK(tx.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));

    const std::string txid = tx.calculateHash();

    std::vector<TransactionInput> altered = tx.getInputs();
    altered[0].scheme = SignatureScheme::ML_DSA_44;

    // Otherwise the scheme byte would be malleable: two different inputs, one id.
    CHECK_NE(withInputs(tx, altered).calculateHash(), txid);
}

GXC_TEST(SignatureScheme, SurvivesSerialization) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();
    CHECK(tx.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));

    Transaction restored;
    CHECK(restored.deserialize(tx.serialize()));

    CHECK(restored.getInputs()[0].scheme == SignatureScheme::ECDSA_SECP256K1);
    CHECK_EQ(restored.getHash(), tx.getHash());
    CHECK(restored.validateSignatures());
}

GXC_TEST(SignatureScheme, PayloadMissingTheSchemeFieldIsRejected) {
    // The field sits mid-record, so it cannot be optional: a missing value
    // would be indistinguishable from the output count that follows it, and
    // the parse would misalign rather than fail. It is mandatory, and its
    // absence is an error.
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();
    CHECK(tx.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));

    std::string payload = tx.serialize();
    const std::string publicKey = tx.getInputs()[0].publicKey;
    const size_t fieldStart = payload.find(publicKey) + publicKey.size() + 1;
    const size_t fieldEnd = payload.find('|', fieldStart);
    payload.erase(fieldStart, fieldEnd - fieldStart + 1);

    Transaction restored;
    // Either the parse fails outright or it produces something that no longer
    // matches the original -- what it must not do is quietly succeed.
    if (restored.deserialize(payload)) {
        CHECK_NE(restored.getHash(), tx.getHash());
    }
}

GXC_TEST(SignatureScheme, UnknownSchemeIdentifierIsRejectedOnDeserialize) {
    const Crypto::KeyPair keys = Crypto::generateKeyPair();
    Transaction tx = buildSpend();
    CHECK(tx.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));

    // Rewrite the scheme field to a value beyond the defined range. Defaulting
    // it to classical would silently downgrade a forward-dated input.
    std::string payload = tx.serialize();
    const std::string publicKey = tx.getInputs()[0].publicKey;
    const size_t fieldStart = payload.find(publicKey) + publicKey.size() + 1;
    const size_t fieldEnd = payload.find('|', fieldStart);
    payload.replace(fieldStart, fieldEnd - fieldStart, "99");

    Transaction restored;
    CHECK_FALSE(restored.deserialize(payload));
}

GXC_TEST(SignatureScheme, DefaultSignInputsKeepsWorking) {
    // The single-argument overload is used throughout the codebase and must
    // remain equivalent to signing under the classical scheme.
    const Crypto::KeyPair keys = Crypto::generateKeyPair();

    Transaction implicitScheme = buildSpend();
    implicitScheme.signInputs(keys.privateKey);

    Transaction explicitScheme = buildSpend();
    explicitScheme.setTimestamp(implicitScheme.getTimestamp());
    explicitScheme.setNonce(implicitScheme.getNonce());
    CHECK(explicitScheme.signInputs(keys.privateKey, SignatureScheme::ECDSA_SECP256K1));

    CHECK(implicitScheme.validateSignatures());
    CHECK(explicitScheme.validateSignatures());
    CHECK_EQ(implicitScheme.computeSignatureHash(), explicitScheme.computeSignatureHash());
}
