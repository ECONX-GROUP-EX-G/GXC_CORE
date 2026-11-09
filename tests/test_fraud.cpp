// Taint propagation and the five fraud rules.
//
// The claim these tests exist to check is a strong one: that tainted funds can
// be followed through the transaction graph by conservation of value rather
// than by heuristics, so that the score attached to a transaction is a fact
// about where its money came from and not an opinion. That claim only holds if
//
//   tau(T_j) = Sum_i w_i * tau(T_i),  w_i = value_from_T_i / total_input_value
//
// really is what the code computes: the weights must sum to one, the result
// must stay inside [0,1], and it must not depend on the order the inputs are
// listed in. Each of those is asserted below against a real mined chain.
//
// The five rules are then checked one at a time, each against a transaction
// built to trip exactly that rule, and -- just as important -- against ones
// that must not trip it.

#include "test_framework.h"
#include "chain_fixture.h"

#include "../include/FraudDetection.h"

#include <algorithm>
#include <string>
#include <vector>

using gxctest::testChain;
using gxctest::TestChain;

namespace {

/** Does `alerts` contain one raised by `rule`? */
bool hasRule(const std::vector<FraudAlert>& alerts, FraudAlert::RuleViolation rule) {
    return std::any_of(alerts.begin(), alerts.end(),
                       [rule](const FraudAlert& a) { return a.rule == rule; });
}

/** The first alert raised by `rule`. */
const FraudAlert& alertFor(const std::vector<FraudAlert>& alerts,
                           FraudAlert::RuleViolation rule) {
    const auto it = std::find_if(alerts.begin(), alerts.end(),
                                 [rule](const FraudAlert& a) { return a.rule == rule; });
    if (it == alerts.end()) {
        throw std::runtime_error("no alert for the requested rule");
    }
    return *it;
}

} // namespace

// ============================================================================
// The seed set
// ============================================================================

GXC_TEST(Taint, StolenTransactionStartsFullyTainted) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    const std::string stolen = fixture.cases[0].theft.getHash();
    CHECK_FALSE(fd.isStolen(stolen));

    fd.markAsStolen(stolen);

    CHECK(fd.isStolen(stolen));
    CHECK_NEAR(fd.getTaintScore(stolen), 1.0, 1e-12);
}

GXC_TEST(Taint, UnrelatedTransactionsStayClean) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    // A different case entirely: no shared ancestry, so no taint.
    CHECK_NEAR(fd.getTaintScore(fixture.cases[1].theft.getHash()), 0.0, 1e-12);
    CHECK_NEAR(fd.getTaintScore(fixture.cases[1].hop.getHash()), 0.0, 1e-12);
}

GXC_TEST(Taint, UnmarkingClearsTheSeed) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    const std::string stolen = fixture.cases[0].theft.getHash();

    fd.markAsStolen(stolen);
    fd.removeFromStolen(stolen);

    CHECK_FALSE(fd.isStolen(stolen));
    CHECK_NEAR(fd.getTaintScore(stolen), 0.0, 1e-12);
}

GXC_TEST(Taint, CoinbaseHasNoTaint) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    // The funding coinbase is the victim's own, upstream of the theft. Taint
    // flows forward along spends only; it must never flow back to the source.
    CHECK_NEAR(fd.getTaintScore(fixture.cases[0].funding.getHash()), 0.0, 1e-12);
}

// ============================================================================
// Propagation
// ============================================================================

GXC_TEST(Taint, PropagatesToDescendantSpend) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    // The hop spends the whole stolen output, so it inherits the whole score.
    CHECK_NEAR(fd.getTaintScore(fixture.cases[0].hop.getHash()), 1.0, 1e-12);
}

GXC_TEST(Taint, AncestryRecordsThePathBackToTheSource) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    const std::string stolen = fixture.cases[0].theft.getHash();
    fd.markAsStolen(stolen);

    const TaintInfo info = fd.getTaintInfo(fixture.cases[0].hop.getHash());

    CHECK_EQ(info.sourceTransaction, stolen);
    CHECK_EQ(info.ancestry.size(), static_cast<size_t>(2));
    CHECK_EQ(info.ancestry.front(), stolen);
    CHECK_EQ(info.ancestry.back(), fixture.cases[0].hop.getHash());
}

GXC_TEST(Taint, ReachesTwoHopsDownstreamByDefault) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.reAggSources[0].theft.getHash());

    // theft -> hop -> re-aggregation.
    CHECK(fd.getTaintScore(fixture.reAggregation.getHash()) > 0.0);
}

// Propagation is bounded, and the bound is what keeps the cost proportional
// to the edges actually touched rather than to the length of the chain. A
// twelve-hop layering chain is two steps longer than the default limit, so
// the cut-off is visible: everything up to the tenth hop is scored, and
// nothing past it is.
GXC_TEST(Taint, PropagationStopsAtTheHopLimit) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.longChainTheft.getHash());

    CHECK_EQ(fixture.longChainHops.size(),
             static_cast<size_t>(TestChain::kLongChainHops));

    for (int i = 0; i < TestChain::kLongChainHops; i++) {
        const double score = fd.getTaintScore(fixture.longChainHops[i].getHash());
        if (i < TestChain::kDefaultMaxHops) {
            CHECK_NEAR(score, 1.0, 1e-12);
        } else {
            CHECK_NEAR(score, 0.0, 1e-12);
        }
    }
}

GXC_TEST(Taint, TaintSurvivesALongLayeringChainUndiluted) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.longChainTheft.getHash());

    // Each hop spends the whole of the previous output, so the weight is 1 at
    // every step: layering through fresh addresses does not wash the funds,
    // which is the property the whole scheme rests on.
    CHECK_NEAR(fd.getTaintScore(fixture.longChainHops[0].getHash()), 1.0, 1e-12);
    CHECK_NEAR(fd.getTaintScore(fixture.longChainHops[9].getHash()), 1.0, 1e-12);
}

// ============================================================================
// The formula itself
// ============================================================================

// The load-bearing test. The re-aggregation combines two equal outputs, only
// one of which is tainted, so the weighted formula has exactly one right
// answer: half.
//
// Dividing by a running subtotal rather than the total input value gives the
// first input a weight of 1.0 and reports 1.0 here -- claiming the whole sum
// is stolen when half of it is clean, which would in turn authorise a reversal
// against twice the funds actually traceable to the theft.
GXC_TEST(Taint, WeightsAreSharesOfTotalInputValue) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.reAggSources[0].theft.getHash());

    const auto& inputs = fixture.reAggregation.getInputs();
    CHECK_EQ(inputs.size(), static_cast<size_t>(2));
    // Equal inputs, so the tainted share is one half.
    CHECK_NEAR(inputs[0].amount, inputs[1].amount, 1e-9);

    CHECK_NEAR(fd.getTaintScore(fixture.reAggregation.getHash()), 0.5, 1e-9);
}

GXC_TEST(Taint, FullyTaintedInputsGiveAFullyTaintedResult) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    // Both contributing branches stolen: the weights sum to one, so the score
    // is one -- not one and a half.
    fd.markAsStolen(fixture.reAggSources[0].theft.getHash());
    fd.markAsStolen(fixture.reAggSources[1].theft.getHash());

    CHECK_NEAR(fd.getTaintScore(fixture.reAggregation.getHash()), 1.0, 1e-9);
}

GXC_TEST(Taint, ScoreNeverExceedsOne) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.reAggSources[0].theft.getHash());
    fd.markAsStolen(fixture.reAggSources[1].theft.getHash());

    // tau is a proportion. A score above 1.0 is not a worse alert, it is a
    // broken invariant -- and the proof validator rejects any proof carrying
    // one, so an out-of-range score silently disables reversal.
    for (const auto& tx : {fixture.reAggSources[0].theft, fixture.reAggSources[0].hop,
                           fixture.reAggSources[1].theft, fixture.reAggSources[1].hop,
                           fixture.reAggregation}) {
        const double score = fd.getTaintScore(tx.getHash());
        CHECK(score >= 0.0);
        CHECK(score <= 1.0);
    }
}

GXC_TEST(Taint, ScoreDoesNotDependOnTheOrderTheBranchesAreMarked) {
    auto& fixture = testChain();

    FraudDetection forward(&fixture.chain);
    forward.markAsStolen(fixture.reAggSources[0].theft.getHash());
    forward.markAsStolen(fixture.reAggSources[1].theft.getHash());

    FraudDetection reverse(&fixture.chain);
    reverse.markAsStolen(fixture.reAggSources[1].theft.getHash());
    reverse.markAsStolen(fixture.reAggSources[0].theft.getHash());

    CHECK_NEAR(forward.getTaintScore(fixture.reAggregation.getHash()),
               reverse.getTaintScore(fixture.reAggregation.getHash()), 1e-12);
}

// ============================================================================
// Rule 1: velocity
// ============================================================================

GXC_TEST(FraudRules, VelocityFiresWhenTaintedFundsMoveImmediately) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    const auto alerts = fd.checkTransaction(fixture.cases[0].hop);

    CHECK(hasRule(alerts, FraudAlert::RuleViolation::VELOCITY_ANOMALY));
    // Full taint, so the alert is at the top of the scale.
    CHECK(alertFor(alerts, FraudAlert::RuleViolation::VELOCITY_ANOMALY).level ==
          FraudAlert::AlertLevel::CRITICAL);
}

GXC_TEST(FraudRules, VelocityIsSilentWhenFundsWereHeld) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.dormant.theft.getHash());

    // Eight days between receiving and spending is not rapid movement.
    const auto alerts = fd.checkTransaction(fixture.dormant.hop);

    CHECK_FALSE(hasRule(alerts, FraudAlert::RuleViolation::VELOCITY_ANOMALY));
}

GXC_TEST(FraudRules, NoRuleFiresOnAnUntaintedTransaction) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    // Nothing marked stolen: the rules must stay quiet rather than reporting
    // on the shape of ordinary traffic.
    CHECK(fd.checkTransaction(fixture.cases[0].hop).empty());
    CHECK(fd.checkTransaction(fixture.fanOut).empty());
    CHECK(fd.checkTransaction(fixture.reAggregation).empty());
}

// ============================================================================
// Rule 2: fan-out
// ============================================================================

GXC_TEST(FraudRules, FanOutFiresWhenTaintedFundsAreSplitManyWays) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[3].theft.getHash());

    CHECK_EQ(fixture.fanOutRecipients.size(), static_cast<size_t>(6));
    const auto alerts = fd.checkTransaction(fixture.fanOut);

    CHECK(hasRule(alerts, FraudAlert::RuleViolation::FAN_OUT_PATTERN));
}

GXC_TEST(FraudRules, FanOutIsSilentOnASingleRecipient) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    const auto alerts = fd.checkTransaction(fixture.cases[0].hop);

    CHECK_FALSE(hasRule(alerts, FraudAlert::RuleViolation::FAN_OUT_PATTERN));
}

// ============================================================================
// Rule 3: re-aggregation
// ============================================================================

GXC_TEST(FraudRules, ReAggregationFiresWhenTaintedOutputsAreRecombined) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.reAggSources[0].theft.getHash());

    const auto alerts = fd.checkTransaction(fixture.reAggregation);

    CHECK(hasRule(alerts, FraudAlert::RuleViolation::RE_AGGREGATION));
}

GXC_TEST(FraudRules, ReAggregationNeedsMoreThanOneInput) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    // The hop has a single input: layering is about combining, so one input
    // can never be a re-aggregation however tainted it is.
    CHECK_EQ(fixture.cases[0].hop.getInputs().size(), static_cast<size_t>(1));
    const auto alerts = fd.checkTransaction(fixture.cases[0].hop);

    CHECK_FALSE(hasRule(alerts, FraudAlert::RuleViolation::RE_AGGREGATION));
}

// ============================================================================
// Rule 4: dormancy
// ============================================================================

GXC_TEST(FraudRules, DormancyFiresWhenHeldFundsSuddenlyMove) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.dormant.theft.getHash());

    const auto alerts = fd.checkTransaction(fixture.dormant.hop);

    CHECK(hasRule(alerts, FraudAlert::RuleViolation::DORMANCY_ACTIVATION));
}

GXC_TEST(FraudRules, DormancyIsSilentOnFundsThatMovedStraightAway) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    // The rule measures how long the funds sat still, not how long ago the
    // score happened to be computed -- so a hop minutes after the theft is
    // not a dormancy event, and will not become one as the record ages.
    const auto alerts = fd.checkTransaction(fixture.cases[0].hop);

    CHECK_FALSE(hasRule(alerts, FraudAlert::RuleViolation::DORMANCY_ACTIVATION));
}

GXC_TEST(FraudRules, DormancyAndVelocityAreMutuallyExclusive) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());
    fd.markAsStolen(fixture.dormant.theft.getHash());

    const auto fast = fd.checkTransaction(fixture.cases[0].hop);
    const auto slow = fd.checkTransaction(fixture.dormant.hop);

    // Both read the same interval, from opposite ends. No transaction should
    // ever be reported as both moving too fast and having sat too long.
    CHECK(hasRule(fast, FraudAlert::RuleViolation::VELOCITY_ANOMALY));
    CHECK_FALSE(hasRule(fast, FraudAlert::RuleViolation::DORMANCY_ACTIVATION));
    CHECK(hasRule(slow, FraudAlert::RuleViolation::DORMANCY_ACTIVATION));
    CHECK_FALSE(hasRule(slow, FraudAlert::RuleViolation::VELOCITY_ANOMALY));
}

// ============================================================================
// Rule 5: clean zone entry
// ============================================================================

GXC_TEST(FraudRules, CleanZoneEntryFiresAndIsAlwaysCritical) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.registerExchange(fixture.mule, "Test Exchange");
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    const auto alerts = fd.checkTransaction(fixture.cases[0].hop);

    CHECK(hasRule(alerts, FraudAlert::RuleViolation::CLEAN_ZONE_ENTRY));
    // Cashing out is the point at which tracing stops working, so severity
    // does not scale with the score here.
    CHECK(alertFor(alerts, FraudAlert::RuleViolation::CLEAN_ZONE_ENTRY).level ==
          FraudAlert::AlertLevel::CRITICAL);
}

GXC_TEST(FraudRules, CleanZoneEntryIsSilentForUnregisteredDestinations) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    const auto alerts = fd.checkTransaction(fixture.cases[0].hop);

    CHECK_FALSE(hasRule(alerts, FraudAlert::RuleViolation::CLEAN_ZONE_ENTRY));
}

GXC_TEST(FraudRules, UnregisteringAZoneStopsTheAlert) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.registerExchange(fixture.mule, "Test Exchange");
    fd.markAsStolen(fixture.cases[0].theft.getHash());
    CHECK(hasRule(fd.checkTransaction(fixture.cases[0].hop),
                  FraudAlert::RuleViolation::CLEAN_ZONE_ENTRY));

    fd.unregisterCleanZone(fixture.mule);

    CHECK_FALSE(fd.isCleanZone(fixture.mule));
    CHECK_FALSE(hasRule(fd.checkTransaction(fixture.cases[0].hop),
                        FraudAlert::RuleViolation::CLEAN_ZONE_ENTRY));
}

// ============================================================================
// Clean zone registry
// ============================================================================

GXC_TEST(CleanZones, EachKindOfZoneIsRecordedUnderItsOwnType) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    fd.registerExchange("tGXCexchange", "Exchange");
    fd.registerStakingPool("tGXCstaking", "Pool");
    fd.registerMerchant("tGXCmerchant", "Shop");
    fd.registerValidator("tGXCvalidator", "Validator");

    CHECK_EQ(fd.getCleanZoneType("tGXCexchange"), std::string("EXCHANGE"));
    CHECK_EQ(fd.getCleanZoneType("tGXCstaking"), std::string("STAKING_POOL"));
    CHECK_EQ(fd.getCleanZoneType("tGXCmerchant"), std::string("MERCHANT"));
    CHECK_EQ(fd.getCleanZoneType("tGXCvalidator"), std::string("VALIDATOR"));
    CHECK_EQ(fd.getAllCleanZones().size(), static_cast<size_t>(4));
}

GXC_TEST(CleanZones, AnUnknownAddressIsNotAZone) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    CHECK_FALSE(fd.isCleanZone("tGXCnobody"));
    CHECK_EQ(fd.getCleanZoneType("tGXCnobody"), std::string("NOT_REGISTERED"));
}

// ============================================================================
// Alerts, flags and statistics
// ============================================================================

GXC_TEST(FraudAlerts, PropagationRaisesAlertsAndRecordsThemByAddress) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.registerExchange(fixture.mule, "Test Exchange");

    fd.markAsStolen(fixture.cases[0].theft.getHash());

    CHECK_FALSE(fd.getAlerts().empty());
    CHECK_FALSE(fd.getAddressAlerts(fixture.mule).empty());
}

GXC_TEST(FraudAlerts, SeverityFilterOnlyReturnsAlertsAtOrAboveTheLevel) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.registerExchange(fixture.mule, "Test Exchange");
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    const auto all = fd.getAlerts(FraudAlert::AlertLevel::LOW);
    const auto critical = fd.getAlerts(FraudAlert::AlertLevel::CRITICAL);

    CHECK(critical.size() <= all.size());
    for (const auto& alert : critical) {
        CHECK(alert.level == FraudAlert::AlertLevel::CRITICAL);
    }
}

GXC_TEST(FraudAlerts, ClearingRemovesBothTheListAndThePerAddressIndex) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.registerExchange(fixture.mule, "Test Exchange");
    fd.markAsStolen(fixture.cases[0].theft.getHash());
    CHECK_FALSE(fd.getAlerts().empty());

    fd.clearAlerts();

    CHECK(fd.getAlerts().empty());
    CHECK(fd.getAddressAlerts(fixture.mule).empty());
}

GXC_TEST(FraudAlerts, StatisticsCountWhatWasRaised) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.registerExchange(fixture.mule, "Test Exchange");
    fd.markAsStolen(fixture.cases[0].theft.getHash());
    fd.flagAddress(fixture.thief, "test");

    const auto stats = fd.getStatistics();

    CHECK_EQ(stats.totalStolenTx, 1u);
    CHECK(stats.totalTaintedTx >= 2u); // the theft and at least its hop
    CHECK_EQ(stats.flaggedAddresses, 1u);
    CHECK_EQ(stats.totalAlerts,
             stats.criticalAlerts + stats.highAlerts + stats.mediumAlerts + stats.lowAlerts);
}

GXC_TEST(AddressFlags, FlaggingIsReversible) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    CHECK_FALSE(fd.isAddressFlagged(fixture.thief));
    fd.flagAddress(fixture.thief, "reported by victim");
    CHECK(fd.isAddressFlagged(fixture.thief));
    CHECK_EQ(fd.getFlaggedAddresses().size(), static_cast<size_t>(1));

    fd.unflagAddress(fixture.thief);

    CHECK_FALSE(fd.isAddressFlagged(fixture.thief));
    CHECK(fd.getFlaggedAddresses().empty());
}

// ============================================================================
// Consensus hooks
// ============================================================================

GXC_TEST(FraudConsensus, CriticallyTaintedTransactionsAreBlocked) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    // Taint at 1.0 is past the 0.8 critical threshold.
    CHECK(fd.shouldBlockTransaction(fixture.cases[0].hop));
}

GXC_TEST(FraudConsensus, CleanTransactionsAreNotBlocked) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    CHECK_FALSE(fd.shouldBlockTransaction(fixture.cases[1].hop));
}

GXC_TEST(FraudConsensus, FlaggingEitherPartyBlocksTheTransaction) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    CHECK_FALSE(fd.shouldBlockTransaction(fixture.cases[1].hop));

    fd.flagAddress(fixture.cases[1].hop.getReceiverAddress(), "sanctioned");

    CHECK(fd.shouldBlockTransaction(fixture.cases[1].hop));
}

GXC_TEST(FraudConsensus, FlaggedAddressesAreFrozen) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    CHECK_FALSE(fd.shouldFreezeAddress(fixture.thief));
    fd.flagAddress(fixture.thief, "test");
    CHECK(fd.shouldFreezeAddress(fixture.thief));
}

// ============================================================================
// Graph tracing
// ============================================================================

GXC_TEST(TaintTracing, APathReachesTheCurrentHolder) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    const auto paths = fd.traceTaintedFlow(fixture.cases[0].theft.getHash(), 20);

    CHECK_FALSE(paths.empty());
    const bool reachesMule =
        std::any_of(paths.begin(), paths.end(), [&](const FraudDetection::FlowPath& p) {
            return !p.addresses.empty() && p.addresses.back() == fixture.mule;
        });
    CHECK(reachesMule);
}

GXC_TEST(TaintTracing, EveryStepOnAPathCarriesItsOwnScore) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);
    fd.markAsStolen(fixture.cases[0].theft.getHash());

    for (const auto& path : fd.traceTaintedFlow(fixture.cases[0].theft.getHash(), 20)) {
        CHECK_EQ(path.taintScores.size(), path.transactions.size());
        for (const double score : path.taintScores) {
            CHECK(score >= 0.0);
            CHECK(score <= 1.0);
        }
        if (!path.taintScores.empty()) {
            CHECK_NEAR(path.finalTaint, path.taintScores.back(), 1e-12);
        }
    }
}

GXC_TEST(TaintTracing, TracingAnUnknownTransactionYieldsNothingUseful) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    const auto paths = fd.traceTaintedFlow("not-a-transaction", 20);

    // One degenerate path at zero taint, and no crash: the proof generator
    // relies on this to refuse rather than to fault.
    for (const auto& path : paths) {
        CHECK_NEAR(path.finalTaint, 0.0, 1e-12);
    }
}

// ============================================================================
// Persistence
// ============================================================================

GXC_TEST(FraudPersistence, ExportedStateRestoresSeedsFlagsAndZones) {
    auto& fixture = testChain();

    FraudDetection original(&fixture.chain);
    original.markAsStolen(fixture.cases[0].theft.getHash());
    original.flagAddress(fixture.thief, "reported");
    original.registerExchange(fixture.mule, "Test Exchange");

    const std::string state = original.exportState();
    CHECK_FALSE(state.empty());

    FraudDetection restored(&fixture.chain);
    restored.importState(state);

    CHECK(restored.isStolen(fixture.cases[0].theft.getHash()));
    CHECK(restored.isAddressFlagged(fixture.thief));
    CHECK(restored.isCleanZone(fixture.mule));
    CHECK_NEAR(restored.getTaintScore(fixture.cases[0].theft.getHash()), 1.0, 1e-9);
}

GXC_TEST(FraudPersistence, ImportingNothingIsHarmless) {
    auto& fixture = testChain();
    FraudDetection fd(&fixture.chain);

    fd.importState("");

    CHECK(fd.getStatistics().totalStolenTx == 0u);
}
