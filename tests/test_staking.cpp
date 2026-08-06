// Staking economics and stake-weighted validator selection.
//
// Selection weight is  w(v) = stake(v) * (days(v)/365)^0.5,  and a validator's
// probability of being chosen is its share of total weight. These tests pin
// down the weighting, the eligibility rules, and the statistical behaviour of
// the selector -- a selector that ignores weight would silently hand equal
// influence to a minimum stake and a whale.

#include "test_framework.h"

#include "../include/Crypto.h"
#include "../include/SalectValidator.h"
#include "../include/Validator.h"

#include <algorithm>
#include <cmath>
#include <map>

namespace {

Validator makeValidator(const std::string& tag, double stake, uint32_t days) {
    return Validator(Crypto::generateAddress(Crypto::sha256(tag), true), stake, days);
}

} // namespace

// ---------------------------------------------------------------------------
// Stake mechanics
// ---------------------------------------------------------------------------

GXC_TEST(Staking, StakingRecordsAmountAndPeriod) {
    Validator v = makeValidator("alice", 500.0, 180);

    CHECK_NEAR(v.getStakeAmount(), 500.0, 1e-9);
    CHECK_EQ(v.getStakingDays(), uint32_t(180));
    CHECK(v.getIsActive());
}

GXC_TEST(Staking, AddingAndRemovingStake) {
    Validator v = makeValidator("bob", 500.0, 180);

    v.addStake(250.0);
    CHECK_NEAR(v.getStakeAmount(), 750.0, 1e-9);

    v.removeStake(200.0);
    CHECK_NEAR(v.getStakeAmount(), 550.0, 1e-9);
}

GXC_TEST(Staking, UnstakingDeactivatesTheValidator) {
    Validator v = makeValidator("carol", 500.0, 180);
    CHECK(v.getIsActive());

    v.unstake();
    CHECK_FALSE(v.getIsActive());
    // An inactive validator contributes no selection weight.
    CHECK_NEAR(v.getWeightedStake(), 0.0, 1e-9);
}

GXC_TEST(Staking, ExtendingThePeriodRaisesWeight) {
    Validator v = makeValidator("dave", 1000.0, 30);
    const double before = v.getWeightedStake();

    v.extendStakingPeriod(300);
    CHECK(v.getWeightedStake() > before);
}

GXC_TEST(Staking, ProtocolLimits) {
    // Documented parameters -- 100 GXC minimum, 14 to 365 day lock.
    CHECK_NEAR(Validator::MIN_STAKE, 100.0, 1e-9);
    CHECK_EQ(Validator::MIN_STAKING_DAYS, uint32_t(14));
    CHECK_EQ(Validator::MAX_STAKING_DAYS, uint32_t(365));
}

// ---------------------------------------------------------------------------
// The weighting formula
// ---------------------------------------------------------------------------

GXC_TEST(Staking, TimeWeightMatchesTheDocumentedFormula) {
    // w = (days / 365) ^ 0.5
    const struct { uint32_t days; double expected; } cases[] = {
        {365, 1.0},
        {180, std::sqrt(180.0 / 365.0)},
        {90,  std::sqrt(90.0 / 365.0)},
        {14,  std::sqrt(14.0 / 365.0)},
    };

    for (const auto& c : cases) {
        Validator v = makeValidator("w" + std::to_string(c.days), 1000.0, c.days);
        CHECK_NEAR(v.getTimeWeight(), c.expected, 1e-9);
    }
}

GXC_TEST(Staking, WeightedStakeIsStakeTimesTimeWeight) {
    Validator v = makeValidator("erin", 2000.0, 180);
    CHECK_NEAR(v.getWeightedStake(), 2000.0 * std::sqrt(180.0 / 365.0), 1e-6);
}

GXC_TEST(Staking, MaximumLockGivesFullWeight) {
    Validator v = makeValidator("frank", 1000.0, 365);
    CHECK_NEAR(v.getTimeWeight(), 1.0, 1e-9);
    CHECK_NEAR(v.getWeightedStake(), 1000.0, 1e-9);
}

GXC_TEST(Staking, TimeBonusHasDiminishingReturns) {
    // The square root is the point: doubling the lock must increase weight, but
    // by less than double, so very long locks cannot dominate outright.
    Validator shortLock = makeValidator("g1", 1000.0, 90);
    Validator longLock = makeValidator("g2", 1000.0, 180);

    const double ratio = longLock.getWeightedStake() / shortLock.getWeightedStake();
    CHECK(ratio > 1.0);
    CHECK(ratio < 2.0);
    CHECK_NEAR(ratio, std::sqrt(2.0), 1e-6);
}

GXC_TEST(Staking, LargerStakeAtEqualDurationWinsProportionally) {
    Validator small = makeValidator("h1", 100.0, 180);
    Validator large = makeValidator("h2", 1000.0, 180);

    CHECK_NEAR(large.getWeightedStake() / small.getWeightedStake(), 10.0, 1e-6);
}

GXC_TEST(Staking, SelectionProbabilitiesSumToOne) {
    std::vector<Validator> pool{
        makeValidator("p1", 100.0, 30),
        makeValidator("p2", 500.0, 180),
        makeValidator("p3", 2500.0, 365),
    };

    double total = 0.0;
    for (const auto& v : pool) total += v.getWeightedStake();

    double probability = 0.0;
    for (const auto& v : pool) {
        const double p = v.getSelectionProbability(total);
        CHECK(p > 0.0);
        CHECK(p <= 1.0);
        probability += p;
    }

    CHECK_NEAR(probability, 1.0, 1e-9);
}

GXC_TEST(Staking, SelectionProbabilityIsZeroWithNoTotalWeight) {
    Validator v = makeValidator("i1", 100.0, 30);
    CHECK_NEAR(v.getSelectionProbability(0.0), 0.0, 1e-9);
}

// ---------------------------------------------------------------------------
// The selector
// ---------------------------------------------------------------------------

GXC_TEST(Staking, SelectorOnlyReturnsPoolMembers) {
    ValidatorSelector selector;
    std::vector<std::string> addresses;

    for (int i = 0; i < 5; i++) {
        Validator v = makeValidator("s" + std::to_string(i), 100.0 * (i + 1), 180);
        addresses.push_back(v.getAddress());
        selector.addValidator(v);
    }

    for (int trial = 0; trial < 50; trial++) {
        const std::string chosen = selector.selectValidator().getAddress();
        CHECK(std::find(addresses.begin(), addresses.end(), chosen) != addresses.end());
    }
}

GXC_TEST(Staking, SelectorFavoursHeavierStakes) {
    // One validator holds ~90% of the weight; over many draws it must be
    // selected far more often than the rest. A selector that ignored weight
    // would land near 25% here.
    ValidatorSelector selector;

    Validator whale = makeValidator("whale", 9000.0, 365);
    selector.addValidator(whale);
    for (int i = 0; i < 3; i++) {
        selector.addValidator(makeValidator("minnow" + std::to_string(i), 333.0, 365));
    }

    const int trials = 2000;
    int whaleWins = 0;
    for (int i = 0; i < trials; i++) {
        if (selector.selectValidator().getAddress() == whale.getAddress()) {
            whaleWins++;
        }
    }

    const double share = static_cast<double>(whaleWins) / trials;
    // Expected share is 9000/9999 ~= 0.90; allow generous slack for randomness.
    CHECK(share > 0.80);
    CHECK(share < 0.98);
}

GXC_TEST(Staking, SelectorEventuallyChoosesEveryEligibleValidator) {
    // Weighting must not starve smaller validators completely -- every active
    // member with non-zero weight has to be reachable.
    ValidatorSelector selector;
    std::map<std::string, int> wins;

    for (int i = 0; i < 4; i++) {
        Validator v = makeValidator("fair" + std::to_string(i), 1000.0, 365);
        wins[v.getAddress()] = 0;
        selector.addValidator(v);
    }

    for (int i = 0; i < 1000; i++) {
        wins[selector.selectValidator().getAddress()]++;
    }

    for (const auto& [address, count] : wins) {
        (void)address;
        CHECK(count > 0);
    }
}

GXC_TEST(Staking, InactiveValidatorsAreExcludedFromWeight) {
    Validator active = makeValidator("j1", 1000.0, 365);
    Validator retired = makeValidator("j2", 1000.0, 365);
    retired.unstake();

    const double total = active.getWeightedStake() + retired.getWeightedStake();
    CHECK_NEAR(total, active.getWeightedStake(), 1e-9);
    CHECK_NEAR(active.getSelectionProbability(total), 1.0, 1e-9);
}

// ---------------------------------------------------------------------------
// Rewards, performance, slashing
// ---------------------------------------------------------------------------

GXC_TEST(Staking, RewardsAccrueAsPendingUntilDistributed) {
    Validator v = makeValidator("k1", 1000.0, 365);
    const double before = v.getTotalRewards();

    v.addReward(12.5);
    v.addReward(7.5);

    // Rewards are staged rather than credited immediately, so a payout run can
    // settle them in one step.
    CHECK_NEAR(v.getTotalRewards(), before, 1e-9);

    v.distributePendingRewards();
    CHECK_NEAR(v.getTotalRewards() - before, 20.0, 1e-9);

    // Distributing again must not double-credit.
    v.distributePendingRewards();
    CHECK_NEAR(v.getTotalRewards() - before, 20.0, 1e-9);
}

GXC_TEST(Staking, ApyIsPositiveForAnActiveStake) {
    Validator v = makeValidator("k2", 1000.0, 365);
    CHECK(v.calculateAPY() > 0.0);
}

GXC_TEST(Staking, LongerLocksEarnAtLeastAsMuch) {
    Validator shortLock = makeValidator("k3", 1000.0, 30);
    Validator longLock = makeValidator("k4", 1000.0, 365);

    CHECK(longLock.calculateAPY() >= shortLock.calculateAPY());
}

GXC_TEST(Staking, BlockProductionIsTracked) {
    Validator v = makeValidator("l1", 1000.0, 365);

    v.recordBlockProduced();
    v.recordBlockProduced();
    v.recordMissedBlock();

    CHECK_EQ(v.getBlocksProduced(), uint32_t(2));
    CHECK_EQ(v.getMissedBlocks(), uint32_t(1));
}

GXC_TEST(Staking, SlashingReducesStake) {
    Validator v = makeValidator("m1", 1000.0, 365);

    v.slash(100.0, "double-signing");

    CHECK(v.getStakeAmount() < 1000.0);
    CHECK_NEAR(v.getStakeAmount(), 900.0, 1e-9);
}

GXC_TEST(Staking, SlashingLowersSelectionWeight) {
    Validator v = makeValidator("m2", 1000.0, 365);
    const double before = v.getWeightedStake();

    v.slash(500.0, "equivocation");

    CHECK(v.getWeightedStake() < before);
}
