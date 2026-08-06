// Tests for the 256-bit integer type that underpins proof-of-work targets and
// cumulative chainwork. Every fork-choice decision depends on this arithmetic
// being exact, so the coverage here is deliberately fussy.

#include "test_framework.h"

#include "../include/arith_uint256.h"

namespace {

arith_uint256 fromHex(const std::string& hex) {
    arith_uint256 value;
    value.SetHex(hex);
    return value;
}

} // namespace

GXC_TEST(ArithUint256, DefaultIsZero) {
    arith_uint256 zero;
    CHECK(zero.IsZero());
    CHECK_EQ(zero.bits(), 0);
    CHECK_EQ(zero.GetHex(), std::string(64, '0'));
}

GXC_TEST(ArithUint256, HexRoundTrip) {
    const std::string hex = "00000000ffff0000000000000000000000000000000000000000000000000000";
    CHECK_EQ(fromHex(hex).GetHex(), hex);
}

GXC_TEST(ArithUint256, HexAcceptsPrefixAndShortInput) {
    CHECK_EQ(fromHex("0x2a").GetLow64(), uint64_t(42));
    CHECK_EQ(fromHex("ff").GetLow64(), uint64_t(255));
    CHECK_EQ(fromHex("").GetLow64(), uint64_t(0));
}

GXC_TEST(ArithUint256, HexIgnoresOverlongInput) {
    // More than 64 significant digits: the low 256 bits are kept, and parsing
    // must not run off the end of the limb array.
    const std::string overlong = std::string(80, 'f');
    arith_uint256 value = fromHex(overlong);
    CHECK_EQ(value.GetHex(), std::string(64, 'f'));
}

GXC_TEST(ArithUint256, Ordering) {
    CHECK(fromHex("01") < fromHex("02"));
    CHECK(fromHex("ff") < fromHex("0100"));
    CHECK(fromHex("02") > fromHex("01"));
    CHECK(fromHex("05") <= fromHex("05"));
    CHECK(fromHex("05") >= fromHex("05"));
    CHECK(fromHex("05") == fromHex("05"));
    CHECK(fromHex("05") != fromHex("06"));

    // Ordering must be driven by the most significant limb, not the least.
    CHECK(fromHex("0000000100000000") > fromHex("00000000ffffffff"));
}

GXC_TEST(ArithUint256, AdditionCarriesAcrossLimbs) {
    arith_uint256 a = fromHex("ffffffff");
    arith_uint256 sum = a + arith_uint256(1);
    CHECK_EQ(sum.GetLow64(), uint64_t(0x100000000ULL));

    // Carry propagating the whole way wraps to zero, modulo 2^256.
    arith_uint256 max = fromHex(std::string(64, 'f'));
    CHECK((max + arith_uint256(1)).IsZero());
}

GXC_TEST(ArithUint256, Subtraction) {
    CHECK_EQ((fromHex("0100") - arith_uint256(1)).GetLow64(), uint64_t(255));
    CHECK((fromHex("05") - fromHex("05")).IsZero());

    // Borrowing across a limb boundary.
    arith_uint256 result = fromHex("0000000100000000") - arith_uint256(1);
    CHECK_EQ(result.GetLow64(), uint64_t(0xffffffffULL));
}

GXC_TEST(ArithUint256, Multiplication) {
    CHECK_EQ((arith_uint256(6) * arith_uint256(7)).GetLow64(), uint64_t(42));
    CHECK((arith_uint256(12345) * arith_uint256(0)).IsZero());

    // A product that spills past 64 bits must land in the higher limbs.
    arith_uint256 big = arith_uint256(0xffffffffULL) * arith_uint256(0xffffffffULL);
    CHECK_EQ(big.GetLow64(), uint64_t(0xfffffffe00000001ULL));
}

GXC_TEST(ArithUint256, Division) {
    CHECK_EQ((arith_uint256(42) / arith_uint256(7)).GetLow64(), uint64_t(6));
    CHECK_EQ((arith_uint256(100) / arith_uint256(7)).GetLow64(), uint64_t(14)); // truncating
    CHECK((arith_uint256(5) / arith_uint256(10)).IsZero());                      // divisor > dividend

    // Division must work when the operands span multiple limbs -- the previous
    // implementation returned a hardcoded 1 for any divisor above 64 bits,
    // which silently corrupted every chainwork calculation.
    arith_uint256 dividend = fromHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    arith_uint256 quotient = dividend / fromHex("0000000000000000000000000000000000000000000000010000000000000000");
    CHECK_EQ(quotient.GetHex(),
             std::string("000000000000000000000000ffff000000000000000000000000000000000000"));
}

GXC_TEST(ArithUint256, DivisionByZeroThrows) {
    CHECK_THROWS(arith_uint256(1) / arith_uint256(0));
}

GXC_TEST(ArithUint256, Shifts) {
    CHECK_EQ((arith_uint256(1) << 8).GetLow64(), uint64_t(256));
    CHECK_EQ((arith_uint256(1) << 32).GetLow64(), uint64_t(0x100000000ULL));
    CHECK_EQ((arith_uint256(256) >> 8).GetLow64(), uint64_t(1));

    // Shifting the top bit down 255 places leaves exactly 1.
    CHECK_EQ(((arith_uint256(1) << 255) >> 255).GetLow64(), uint64_t(1));

    // Shifting past the width yields zero rather than undefined behaviour.
    CHECK((arith_uint256(1) << 256).IsZero());
    CHECK((arith_uint256(1) >> 256).IsZero());
}

GXC_TEST(ArithUint256, BitsCountsHighestSetBit) {
    CHECK_EQ(arith_uint256(0).bits(), 0);
    CHECK_EQ(arith_uint256(1).bits(), 1);
    CHECK_EQ(arith_uint256(255).bits(), 8);
    CHECK_EQ(arith_uint256(256).bits(), 9);
    // Bit 255 set: exercises the 1U<<31 path that was signed-overflow UB before.
    CHECK_EQ((arith_uint256(1) << 255).bits(), 256);
}

GXC_TEST(ArithUint256, CompactDecodesBitcoinTarget) {
    // 0x1d00ffff is Bitcoin's difficulty-1 target. The old SetCompact never
    // applied the exponent shift, so it decoded to 0xffff instead of a 224-bit
    // value -- which is what made every target comparison meaningless.
    arith_uint256 target;
    target.SetCompact(0x1d00ffff);
    CHECK_EQ(target.GetHex(),
             std::string("00000000ffff0000000000000000000000000000000000000000000000000000"));
}

GXC_TEST(ArithUint256, CompactRoundTrips) {
    for (uint32_t bits : {0x1d00ffffU, 0x1b0404cbU, 0x207fffffU, 0x1e0ffff0U}) {
        arith_uint256 target;
        target.SetCompact(bits);
        CHECK_EQ(target.GetCompact(), bits);
    }
}

GXC_TEST(ArithUint256, CompactSmallExponents) {
    arith_uint256 target;
    target.SetCompact(0x01003456);
    CHECK_EQ(target.GetLow64(), uint64_t(0x00));

    target.SetCompact(0x02008000);
    CHECK_EQ(target.GetLow64(), uint64_t(0x80));

    target.SetCompact(0x03123456);
    CHECK_EQ(target.GetLow64(), uint64_t(0x123456));
}

GXC_TEST(ArithUint256, CompactFlagsNegativeAndOverflow) {
    bool negative = false;
    bool overflow = false;
    arith_uint256 target;

    target.SetCompact(0x01fedcba, &negative, &overflow);
    CHECK(negative);
    CHECK_FALSE(overflow);

    target.SetCompact(0xff123456, &negative, &overflow);
    CHECK(overflow);
}

GXC_TEST(ArithUint256, PowLimitDiffersByNetwork) {
    const arith_uint256 mainnet = PowLimit(false);
    const arith_uint256 testnet = PowLimit(true);

    // Testnet's limit must be far easier, otherwise a developer cannot mine.
    CHECK(testnet > mainnet);
    CHECK_EQ(PowLimitBits(false), 0x1d00ffffU);
}

GXC_TEST(ArithUint256, DifficultyOneIsThePowLimit) {
    CHECK_EQ(DifficultyToTarget(1.0, false).GetHex(), PowLimit(false).GetHex());
    CHECK_EQ(DifficultyToTarget(1.0, true).GetHex(), PowLimit(true).GetHex());
}

GXC_TEST(ArithUint256, HigherDifficultyMeansSmallerTarget) {
    const arith_uint256 easy = DifficultyToTarget(1.0, false);
    const arith_uint256 medium = DifficultyToTarget(1000.0, false);
    const arith_uint256 hard = DifficultyToTarget(1000000.0, false);

    CHECK(medium < easy);
    CHECK(hard < medium);
    CHECK_FALSE(hard.IsZero());
}

GXC_TEST(ArithUint256, DifficultyToTargetRoundTrips) {
    for (double difficulty : {1.0, 2.0, 16.0, 1000.0, 65536.0}) {
        const arith_uint256 target = DifficultyToTarget(difficulty, false);
        CHECK_NEAR(TargetToDifficulty(target, false), difficulty, difficulty * 1e-6);
    }
}

GXC_TEST(ArithUint256, DifficultyToTargetHandlesDegenerateInput) {
    // Zero and negative difficulty are meaningless; they must clamp to the
    // easiest target rather than divide by zero or wrap around.
    CHECK_EQ(DifficultyToTarget(0.0, false).GetHex(), PowLimit(false).GetHex());
    CHECK_EQ(DifficultyToTarget(-5.0, false).GetHex(), PowLimit(false).GetHex());
    CHECK_FALSE(DifficultyToTarget(1e30, false).IsZero());
}

GXC_TEST(ArithUint256, BlockProofRisesWithDifficulty) {
    const arith_uint256 easyWork = GetBlockProof(1.0, false);
    const arith_uint256 hardWork = GetBlockProof(1000.0, false);

    CHECK(hardWork > easyWork);
    CHECK_FALSE(easyWork.IsZero());
}

GXC_TEST(ArithUint256, ChainworkAccumulates) {
    // Fork choice compares summed work, so addition over many blocks has to stay
    // monotonic and must not overflow at realistic heights.
    arith_uint256 total;
    const arith_uint256 perBlock = GetBlockProof(1000.0, false);

    for (int i = 0; i < 10000; i++) {
        const arith_uint256 previous = total;
        total += perBlock;
        CHECK(total > previous);
    }
}
