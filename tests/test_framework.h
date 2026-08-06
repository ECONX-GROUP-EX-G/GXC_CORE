#pragma once

// A dependency-free test harness.
//
// GXC-CORE builds with nothing but OpenSSL and LevelDB, and the test suite is
// meant to stay runnable in that same environment -- no GoogleTest fetch, no
// network access during configure. Tests self-register at static-init time and
// the runner in test_main.cpp executes them.
//
//   GXC_TEST(Suite, name) {
//       CHECK(condition);
//       CHECK_EQ(actual, expected);
//   }

#include <cmath>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace gxctest {

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void()> fn;
};

/** Thrown by a failing assertion; caught by the runner. */
struct AssertionFailure {
    std::string message;
};

std::vector<TestCase>& registry();

struct Registrar {
    Registrar(const char* suite, const char* name, std::function<void()> fn);
};

/**
 * Run every registered test whose "Suite.name" contains `filter`.
 * @return process exit status: 0 when all tests pass.
 */
int runAll(const std::string& filter);

/** Render a value for an assertion message. */
template <typename T>
std::string describe(const T& value) {
    std::ostringstream ss;
    ss << value;
    return ss.str();
}

inline std::string describe(bool value) { return value ? "true" : "false"; }

inline std::string describe(const std::string& value) { return "\"" + value + "\""; }

[[noreturn]] void failAssertion(const char* file, int line, const std::string& message);

/** Compare doubles with an absolute tolerance rather than exact equality. */
inline bool nearlyEqual(double a, double b, double epsilon = 1e-9) {
    return std::fabs(a - b) <= epsilon;
}

} // namespace gxctest

#define GXC_TEST(suite_name, test_name)                                                   \
    static void gxc_test_##suite_name##_##test_name();                                    \
    static ::gxctest::Registrar gxc_reg_##suite_name##_##test_name(                       \
        #suite_name, #test_name, gxc_test_##suite_name##_##test_name);                    \
    static void gxc_test_##suite_name##_##test_name()

#define CHECK(condition)                                                                  \
    do {                                                                                  \
        if (!(condition)) {                                                               \
            ::gxctest::failAssertion(__FILE__, __LINE__,                                  \
                                     "CHECK failed: " #condition);                        \
        }                                                                                 \
    } while (false)

#define CHECK_FALSE(condition)                                                            \
    do {                                                                                  \
        if ((condition)) {                                                                \
            ::gxctest::failAssertion(__FILE__, __LINE__,                                  \
                                     "CHECK_FALSE failed: " #condition);                  \
        }                                                                                 \
    } while (false)

#define CHECK_EQ(actual, expected)                                                        \
    do {                                                                                  \
        const auto& gxc_a = (actual);                                                     \
        const auto& gxc_b = (expected);                                                   \
        if (!(gxc_a == gxc_b)) {                                                          \
            ::gxctest::failAssertion(__FILE__, __LINE__,                                  \
                "CHECK_EQ failed: " #actual " == " #expected                              \
                "\n      actual:   " + ::gxctest::describe(gxc_a) +                       \
                "\n      expected: " + ::gxctest::describe(gxc_b));                       \
        }                                                                                 \
    } while (false)

#define CHECK_NE(actual, unexpected)                                                      \
    do {                                                                                  \
        const auto& gxc_a = (actual);                                                     \
        const auto& gxc_b = (unexpected);                                                 \
        if (gxc_a == gxc_b) {                                                             \
            ::gxctest::failAssertion(__FILE__, __LINE__,                                  \
                "CHECK_NE failed: " #actual " != " #unexpected                            \
                "\n      both were: " + ::gxctest::describe(gxc_a));                      \
        }                                                                                 \
    } while (false)

#define CHECK_NEAR(actual, expected, epsilon)                                             \
    do {                                                                                  \
        const double gxc_a = (actual);                                                    \
        const double gxc_b = (expected);                                                  \
        if (!::gxctest::nearlyEqual(gxc_a, gxc_b, (epsilon))) {                           \
            ::gxctest::failAssertion(__FILE__, __LINE__,                                  \
                "CHECK_NEAR failed: " #actual " ~= " #expected                            \
                "\n      actual:   " + ::gxctest::describe(gxc_a) +                       \
                "\n      expected: " + ::gxctest::describe(gxc_b));                       \
        }                                                                                 \
    } while (false)

#define CHECK_THROWS(expression)                                                          \
    do {                                                                                  \
        bool gxc_threw = false;                                                           \
        try {                                                                             \
            (void)(expression);                                                           \
        } catch (const ::gxctest::AssertionFailure&) {                                    \
            throw;                                                                        \
        } catch (...) {                                                                   \
            gxc_threw = true;                                                             \
        }                                                                                 \
        if (!gxc_threw) {                                                                 \
            ::gxctest::failAssertion(__FILE__, __LINE__,                                  \
                "CHECK_THROWS failed: " #expression " did not throw");                    \
        }                                                                                 \
    } while (false)
