#include "test_framework.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>

namespace gxctest {

std::vector<TestCase>& registry() {
    // Function-local static: guarantees the vector is constructed before the
    // first Registrar runs, whatever order the translation units initialize in.
    static std::vector<TestCase> tests;
    return tests;
}

Registrar::Registrar(const char* suite, const char* name, std::function<void()> fn) {
    registry().push_back(TestCase{suite, name, std::move(fn)});
}

void failAssertion(const char* file, int line, const std::string& message) {
    std::ostringstream ss;
    const char* base = std::strrchr(file, '/');
    ss << (base ? base + 1 : file) << ":" << line << "\n      " << message;
    throw AssertionFailure{ss.str()};
}

namespace {

constexpr const char* GREEN = "\033[32m";
constexpr const char* RED = "\033[31m";
constexpr const char* DIM = "\033[2m";
constexpr const char* BOLD = "\033[1m";
constexpr const char* RESET = "\033[0m";

} // namespace

int runAll(const std::string& filter) {
    auto& tests = registry();
    std::stable_sort(tests.begin(), tests.end(), [](const TestCase& a, const TestCase& b) {
        return a.suite < b.suite;
    });

    size_t passed = 0;
    size_t failed = 0;
    size_t skipped = 0;
    std::vector<std::string> failures;
    std::string currentSuite;

    const auto started = std::chrono::steady_clock::now();

    for (const auto& test : tests) {
        const std::string fullName = test.suite + "." + test.name;
        if (!filter.empty() && fullName.find(filter) == std::string::npos) {
            skipped++;
            continue;
        }

        if (test.suite != currentSuite) {
            currentSuite = test.suite;
            std::cout << "\n" << BOLD << currentSuite << RESET << "\n";
        }

        std::string error;
        try {
            test.fn();
        } catch (const AssertionFailure& e) {
            error = e.message;
        } catch (const std::exception& e) {
            error = std::string("unexpected exception: ") + e.what();
        } catch (...) {
            error = "unexpected non-standard exception";
        }

        if (error.empty()) {
            passed++;
            std::cout << "  " << GREEN << "PASS" << RESET << "  " << test.name << "\n";
        } else {
            failed++;
            std::cout << "  " << RED << "FAIL" << RESET << "  " << test.name << "\n";
            std::cout << DIM << "        " << error << RESET << "\n";
            failures.push_back(fullName);
        }
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    std::cout << "\n" << BOLD << "────────────────────────────────────────" << RESET << "\n";
    std::cout << passed << " passed";
    if (failed) std::cout << ", " << RED << failed << " failed" << RESET;
    if (skipped) std::cout << ", " << skipped << " filtered out";
    std::cout << "  " << DIM << "(" << elapsed << " ms)" << RESET << "\n";

    if (!failures.empty()) {
        std::cout << "\n" << RED << "Failing tests:" << RESET << "\n";
        for (const auto& name : failures) {
            std::cout << "  - " << name << "\n";
        }
    }

    return failed == 0 ? 0 : 1;
}

} // namespace gxctest

int main(int argc, char** argv) {
    // Optional single argument: a substring filter over "Suite.name".
    const std::string filter = (argc > 1) ? argv[1] : "";

    std::cout << "\033[1mGXC-CORE test suite\033[0m\n";
    if (!filter.empty()) {
        std::cout << "filter: " << filter << "\n";
    }

    return gxctest::runAll(filter);
}
