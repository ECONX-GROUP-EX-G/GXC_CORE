// The reversal pipeline: fee pool, Proof of Feasibility, and execution.
//
// A reversal is the most dangerous operation in the protocol -- it moves
// somebody's funds without their signature -- so the tests here are weighted
// towards the ways it must refuse. The order of business is:
//
//   1. the fee pool's accounting, which gates every reversal;
//   2. proof generation, which must refuse anything it cannot evidence;
//   3. proof validation, which must reject a proof altered after approval;
//   4. execution, which must be idempotent against replay.
//
// Two tests below deliberately pin behaviour that is *not* what the design
// documents promise, rather than asserting the promise and failing. Each says
// so in its comment and names what is missing. They are written that way so
// the gap is visible in the suite output instead of living only in prose.

#include "test_framework.h"
#include "chain_fixture.h"

#include "../include/FraudDetection.h"
#include "../include/ProofGenerator.h"
#include "../include/ReversalExecutor.h"
#include "../include/ReversalFeePool.h"
#include "../include/Utils.h"

#include <cstdint>
#include <memory>
#include <string>

using gxctest::testChain;

namespace {

/** STANDARD_FEE in ReversalExecutor: 0.00001 GXC. */
constexpr uint64_t kStandardFee = 1000;

/** min_fee_amount in ReversalFeePool. */
constexpr uint64_t kMinFee = 1000;

/** min_balance_warning in ReversalFeePool: 1 GXC. */
constexpr uint64_t kLowBalanceThreshold = 100000000;

/** Enough to cover many reversals. */
constexpr uint64_t kSeedFunding = 100000000;

/** The whole reversal subsystem, wired up as production does it. */
struct ReversalStack {
    FraudDetection fraud;
    ReversalFeePool pool;
    std::unique_ptr<ProofGenerator> proofs;
    std::unique_ptr<ReversalExecutor> executor;

    explicit ReversalStack(Blockchain* chain, uint64_t funding = kSeedFunding)
        : fraud(chain) {
        pool.initialize("tGXCreversalpool");
        if (funding > 0) {
            // A 100% split of a synthetic fee is the one funding path that
            // credits the pool's live balance; see the asymmetry test below.
            pool.depositTransactionFeeSplit("seed-funding", funding, 1.0);
        }
        proofs = std::make_unique<ProofGenerator>(chain, &fraud);
        executor = std::make_unique<ReversalExecutor>(chain, proofs.get(), &pool);
        fraud.setReversalSystem(proofs.get(), executor.get());
    }
};

} // namespace

// ============================================================================
// Fee pool
// ============================================================================

GXC_TEST(ReversalFeePool, StartsEmptyAndRefusesToPay) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");

    CHECK_EQ(pool.getBalance(), static_cast<uint64_t>(0));
    CHECK_FALSE(pool.hasSufficientFunds(kStandardFee));
    CHECK(pool.isBalanceLow());
    CHECK_FALSE(pool.deductFee("rtx", kStandardFee, "tGXCvictim", "admin"));
}

GXC_TEST(ReversalFeePool, FeeSplitCreditsItsShareOfATransactionFee) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");

    // The default split is 15% of a transaction's fee.
    const uint64_t credited = pool.depositTransactionFeeSplit("tx-1", 1000000, 0.15);

    CHECK_EQ(credited, static_cast<uint64_t>(150000));
    CHECK_EQ(pool.getBalance(), static_cast<uint64_t>(150000));
    CHECK_EQ(pool.getTotalFunded(), static_cast<uint64_t>(150000));
}

GXC_TEST(ReversalFeePool, ADustFeeCreditsNothing) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");

    // 15% of 5 satoshis truncates to zero; the pool must not record a
    // zero-value funding event.
    CHECK_EQ(pool.depositTransactionFeeSplit("tx-dust", 5, 0.15), static_cast<uint64_t>(0));
    CHECK_EQ(pool.getBalance(), static_cast<uint64_t>(0));
}

GXC_TEST(ReversalFeePool, DeductingAFeeMovesBalanceToSpent) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");
    pool.depositTransactionFeeSplit("seed", kSeedFunding, 1.0);

    CHECK(pool.deductFee("rtx-1", kStandardFee, "tGXCvictim", "admin-1"));

    CHECK_EQ(pool.getBalance(), kSeedFunding - kStandardFee);
    CHECK_EQ(pool.getTotalSpent(), kStandardFee);
    // Nothing appears or disappears: what was funded is what is held plus
    // what has been paid out.
    CHECK_EQ(pool.getTotalFunded(), pool.getBalance() + pool.getTotalSpent());
}

GXC_TEST(ReversalFeePool, WillNotPayMoreThanItHolds) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");
    pool.depositTransactionFeeSplit("seed", 5000, 1.0);

    CHECK_FALSE(pool.deductFee("rtx", 6000, "tGXCvictim", "admin"));

    // A refused payment must leave the books untouched.
    CHECK_EQ(pool.getBalance(), static_cast<uint64_t>(5000));
    CHECK_EQ(pool.getTotalSpent(), static_cast<uint64_t>(0));
}

GXC_TEST(ReversalFeePool, RejectsAFeeBelowTheMinimum) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");
    pool.depositTransactionFeeSplit("seed", kSeedFunding, 1.0);

    CHECK_FALSE(pool.deductFee("rtx", kMinFee - 1, "tGXCvictim", "admin"));
    CHECK_EQ(pool.getBalance(), kSeedFunding);
}

GXC_TEST(ReversalFeePool, AverageFeeTracksTheReversalsPaidFor) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");
    pool.depositTransactionFeeSplit("seed", kSeedFunding, 1.0);

    CHECK_EQ(pool.getAverageFee(), static_cast<uint64_t>(0)); // none yet
    CHECK(pool.deductFee("rtx-1", 1000, "tGXCvictim", "admin"));
    CHECK(pool.deductFee("rtx-2", 3000, "tGXCvictim", "admin"));

    CHECK_EQ(pool.getAverageFee(), static_cast<uint64_t>(2000));
}

GXC_TEST(ReversalFeePool, LowBalanceIsReportedAtTheWarningThreshold) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");

    pool.updateBalanceFromBlockchain(kLowBalanceThreshold);
    CHECK_FALSE(pool.isBalanceLow());

    pool.updateBalanceFromBlockchain(kLowBalanceThreshold - 1);
    CHECK(pool.isBalanceLow());
}

GXC_TEST(ReversalFeePool, ExecutionFeeIsAShareOfWhatWasRecovered) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");

    // 0.2% of one recovered GXC, in satoshis.
    const uint64_t deposited =
        pool.depositReversalExecutionFee("rtx", Utils::SATOSHIS_PER_COIN, 0.002);

    CHECK_EQ(deposited, static_cast<uint64_t>(200000));
    CHECK_EQ(pool.getBalance(), static_cast<uint64_t>(200000));
}

// The two funding paths disagree about what current_balance means, and this
// test exists to make that visible rather than to bless it.
//
// depositTransactionFeeSplit() credits the live balance; recordFunding() --
// the path for an operator topping the pool up on chain -- records the amount
// against total_funded but leaves the balance alone, on the assumption that
// updateBalanceFromBlockchain() will later supply the real figure. Until that
// sync happens the pool will refuse to pay out against money it has been told
// it received. Whether the balance is chain-derived or ledger-derived is a
// decision for the protocol owners; today the code does both.
GXC_TEST(ReversalFeePool, ManualFundingDoesNotCreditTheLiveBalance) {
    ReversalFeePool pool;
    pool.initialize("tGXCpool");

    pool.recordFunding("fund-tx", "tGXCoperator", kSeedFunding, "top-up");

    CHECK_EQ(pool.getTotalFunded(), kSeedFunding);
    CHECK_EQ(pool.getBalance(), static_cast<uint64_t>(0));
    CHECK_FALSE(pool.hasSufficientFunds(kStandardFee));

    // The sync is what makes the money spendable.
    pool.updateBalanceFromBlockchain(kSeedFunding);
    CHECK(pool.hasSufficientFunds(kStandardFee));
}

// ============================================================================
// Proof generation: the refusals
// ============================================================================

GXC_TEST(ReversalProof, RefusesATransactionNobodyReportedStolen) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);

    // No markAsStolen: there is no victim claim to act on.
    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    CHECK(proof.proof_type.empty());
    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

GXC_TEST(ReversalProof, RefusesATransactionThatIsNotOnChain) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen("0000000000000000000000000000000000000000000000000000000000000000");

    const auto proof = stack.fraud.generateReversalProof(
        "0000000000000000000000000000000000000000000000000000000000000000",
        fixture.mule, "admin-1", "sig");

    CHECK(proof.proof_type.empty());
}

GXC_TEST(ReversalProof, RefusesAHolderWithNoTraceableConnection) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());

    // The miner never touched these funds, so no path reaches him.
    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.miner, "admin-1", "sig");

    CHECK(proof.proof_type.empty());
}

// A limitation, pinned deliberately. Proof generation requires a *path* whose
// last address is the current holder, and a path only gains an address when
// taint moves on to a further transaction. So funds still sitting where the
// thief received them -- the fastest case to report, and the easiest to
// recover -- cannot be proved against at all. Only funds that have already
// been layered onward can.
GXC_TEST(ReversalProof, CannotActOnFundsTheThiefStillHolds) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);

    // cases[2] has no onward hop: the thief is the current holder.
    stack.fraud.markAsStolen(fixture.cases[2].theft.getHash());
    CHECK_NEAR(stack.fraud.getTaintScore(fixture.cases[2].theft.getHash()), 1.0, 1e-12);

    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[2].theft.getHash(), fixture.thief, "admin-1", "sig");

    CHECK(proof.proof_type.empty());
}

GXC_TEST(ReversalProof, RefusesWithoutTheReversalComponentsWiredUp) {
    auto& fixture = testChain();

    // A FraudDetection that was never given a generator or an executor. The
    // guards must see null and fail closed rather than calling through an
    // indeterminate pointer.
    FraudDetection bare(&fixture.chain);
    bare.markAsStolen(fixture.cases[0].theft.getHash());

    const auto proof = bare.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    CHECK(proof.proof_type.empty());
    CHECK_FALSE(bare.validateReversalProof(proof));
    CHECK_FALSE(bare.executeReversal(proof));
}

// ============================================================================
// Proof generation: the successful case
// ============================================================================

GXC_TEST(ReversalProof, ProvesAReversalAgainstALayeredHolder) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());

    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "signature-bytes");

    CHECK_EQ(proof.proof_type, std::string("REVERSAL_PROOF"));
    CHECK_EQ(proof.stolen_tx, fixture.cases[0].theft.getHash());
    CHECK_EQ(proof.current_holder, fixture.mule);
    // The victim is the party the stolen transaction debited.
    CHECK_EQ(proof.origin_owner, fixture.victim);
    CHECK_EQ(proof.approved_by, std::string("admin-1"));
    CHECK_NEAR(proof.taint_score, 1.0, 1e-12);
    CHECK_FALSE(proof.proof_hash.empty());
    CHECK_FALSE(proof.trace_path.empty());
    CHECK_EQ(proof.trace_path.front(), fixture.cases[0].theft.getHash());
}

GXC_TEST(ReversalProof, RecoverableAmountIsTaintTimesBalanceInSatoshis) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());

    const double balance = fixture.chain.getBalance(fixture.mule);
    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    // R = tau * Balance, carried in satoshis like every other amount on this
    // path. Truncating to whole GXC instead would quietly abandon the
    // fractional part of the victim's claim.
    const uint64_t expected = static_cast<uint64_t>(
        proof.taint_score * balance * static_cast<double>(Utils::SATOSHIS_PER_COIN));

    CHECK_EQ(proof.recoverable_amount, expected);
    CHECK(proof.recoverable_amount > Utils::SATOSHIS_PER_COIN); // far above 1 GXC
}

// Pinned deliberately: R = tau x Balance measures the holder's whole balance,
// not the amount actually traced from the theft.
//
// tau is the taint of one transaction, but it is multiplied by everything the
// holder owns. Here the mule received three separate tainted hops and the
// proof is raised against one of them, so the recoverable figure comes out at
// the mule's entire balance -- roughly three times the sum this theft can
// account for. With an innocent balance mixed in it would be clawed back too.
//
// Sound alternatives exist (cap the recovery at the traced value, or carry a
// tainted-value figure alongside the ratio), but choosing one is a policy
// decision for the protocol owners, not a code cleanup. This records what the
// formula does today.
GXC_TEST(ReversalProof, RecoveryIsNotCappedAtTheTracedAmount) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());

    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");
    CHECK_EQ(proof.proof_type, std::string("REVERSAL_PROOF"));

    // What this theft actually put into the mule's hands.
    const double traced = fixture.cases[0].hop.getOutputs()[0].amount;
    const double recoverable = static_cast<double>(proof.recoverable_amount) /
                               static_cast<double>(Utils::SATOSHIS_PER_COIN);

    CHECK(recoverable > traced);
    // And it is the holder's full balance, to within the conversion.
    CHECK_NEAR(recoverable, fixture.chain.getBalance(fixture.mule), 1e-6);
}

GXC_TEST(ReversalProof, AFreshProofValidates) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());

    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    CHECK(stack.fraud.validateReversalProof(proof));
}

// ============================================================================
// Proof validation: tamper detection
// ============================================================================

GXC_TEST(ReversalProofValidation, RejectsAnInflatedAmount) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());
    auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");
    CHECK(stack.fraud.validateReversalProof(proof));

    proof.recoverable_amount *= 2;

    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

GXC_TEST(ReversalProofValidation, RejectsARedirectedVictim) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());
    auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    // The payee is inside the hash, so funds cannot be re-pointed after
    // approval.
    proof.origin_owner = fixture.thief;

    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

GXC_TEST(ReversalProofValidation, RejectsASubstitutedApprover) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());
    auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    proof.approved_by = "admin-2";

    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

GXC_TEST(ReversalProofValidation, RejectsAnEmptySignature) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());

    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "");

    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

GXC_TEST(ReversalProofValidation, RejectsAnOutOfRangeTaintScore) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());
    auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    // tau is a proportion; 1.5 is not a stronger claim, it is a broken one.
    proof.taint_score = 1.5;

    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

GXC_TEST(ReversalProofValidation, RejectsAProofOfTheWrongType) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());
    auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");

    proof.proof_type = "SOMETHING_ELSE";

    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

GXC_TEST(ReversalProofValidation, RejectsAProofWhoseClaimWasWithdrawn) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    const std::string stolen = fixture.cases[0].theft.getHash();
    stack.fraud.markAsStolen(stolen);
    const auto proof =
        stack.fraud.generateReversalProof(stolen, fixture.mule, "admin-1", "sig");
    CHECK(stack.fraud.validateReversalProof(proof));

    // The victim withdraws the report: an already-issued proof must stop
    // validating rather than remaining executable.
    stack.fraud.removeFromStolen(stolen);

    CHECK_FALSE(stack.fraud.validateReversalProof(proof));
}

// Pinned deliberately: authorisation is the weakest link in this pipeline.
//
// validateProof() checks only that approval_signature is non-empty -- it is
// never verified against an admin key, and the proof hash is computed over
// whatever signature string is supplied. So anyone able to call the generator
// can mint a proof that validates, and a single approver is sufficient. The
// m-of-n threshold the design calls for does not exist in code. This test
// records that as it stands today; it should be inverted once signatures are
// actually verified.
GXC_TEST(ReversalProofValidation, AnyNonEmptySignatureIsAcceptedToday) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());

    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule,
        "not-a-real-admin", "not-a-real-signature");

    CHECK(stack.fraud.validateReversalProof(proof));
}

// ============================================================================
// Execution
// ============================================================================

GXC_TEST(ReversalExecution, RefusesToExecuteAnInvalidProof) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);

    CHECK_FALSE(stack.fraud.executeReversal(ProofOfFeasibility()));
}

GXC_TEST(ReversalExecution, RefusesWhenTheFeePoolCannotCoverTheFee) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain, 0); // unfunded pool
    stack.fraud.markAsStolen(fixture.cases[0].theft.getHash());
    const auto proof = stack.fraud.generateReversalProof(
        fixture.cases[0].theft.getHash(), fixture.mule, "admin-1", "sig");
    CHECK_EQ(proof.proof_type, std::string("REVERSAL_PROOF"));

    CHECK_FALSE(stack.fraud.executeReversal(proof));
    CHECK_FALSE(fixture.chain.isTransactionReversed(fixture.cases[0].theft.getHash()));
}

// The end-to-end case. This one mutates chain state, so it owns cases[1]
// exclusively -- no other test may reverse against it.
GXC_TEST(ReversalExecution, ExecutesOnceAndRefusesTheReplay) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    const std::string stolen = fixture.cases[1].theft.getHash();
    stack.fraud.markAsStolen(stolen);

    const auto proof =
        stack.fraud.generateReversalProof(stolen, fixture.mule, "admin-1", "sig");
    CHECK_EQ(proof.proof_type, std::string("REVERSAL_PROOF"));

    const uint64_t poolBefore = stack.pool.getBalance();
    CHECK_FALSE(fixture.chain.isTransactionReversed(stolen));

    CHECK(stack.fraud.executeReversal(proof));

    // The fee came out of the pool, and the execution levy went back in.
    CHECK(stack.pool.getTotalSpent() >= kStandardFee);
    CHECK_NE(stack.pool.getBalance(), poolBefore);

    // The stolen transaction is now marked, which is what stops a second run.
    CHECK(fixture.chain.isTransactionReversed(stolen));

    // Replaying the same proof must not pay out twice.
    CHECK_FALSE(stack.fraud.executeReversal(proof));

    // And a fresh proof for the same theft cannot even be minted.
    const auto again =
        stack.fraud.generateReversalProof(stolen, fixture.mule, "admin-1", "sig");
    CHECK(again.proof_type.empty());
}

// Pinned deliberately: a reversal that reports success moves no money.
//
// ReversalExecutor::debitAccount() and creditAccount() log their intent and
// return true without touching the UTXO set, and
// Blockchain::addReversalTransaction() checks the holder's balance and then
// also only logs. So the pipeline validates a proof, charges the fee pool and
// records the transaction as reversed -- while the victim's balance and the
// holder's balance both stay exactly where they were.
//
// Everything upstream of the ledger write is real and tested above; the ledger
// write itself is not implemented. This test asserts what the code actually
// does so the gap cannot be mistaken for a working recovery.
GXC_TEST(ReversalExecution, DoesNotYetMoveAnyFunds) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);
    const std::string stolen = fixture.dormant.theft.getHash();
    stack.fraud.markAsStolen(stolen);

    const double victimBefore = fixture.chain.getBalance(fixture.victim);
    const double holderBefore = fixture.chain.getBalance(fixture.mule);

    const auto proof =
        stack.fraud.generateReversalProof(stolen, fixture.mule, "admin-1", "sig");
    CHECK_EQ(proof.proof_type, std::string("REVERSAL_PROOF"));
    CHECK(proof.recoverable_amount > 0);
    CHECK(stack.fraud.executeReversal(proof));

    CHECK_NEAR(fixture.chain.getBalance(fixture.victim), victimBefore, 1e-9);
    CHECK_NEAR(fixture.chain.getBalance(fixture.mule), holderBefore, 1e-9);
}

// ============================================================================
// Configuration surface
// ============================================================================

GXC_TEST(ReversalConfig, PublishedLimitsMatchTheDocumentedPolicy) {
    auto& fixture = testChain();
    ReversalStack stack(&fixture.chain);

    CHECK_EQ(stack.proofs->getMaxTraceHops(), 20u);
    CHECK_EQ(stack.proofs->getReversalWindow(), 20000u); // ~30 days of blocks
    CHECK_NEAR(stack.proofs->getMinTaintThreshold(), 0.1, 1e-12);
}
