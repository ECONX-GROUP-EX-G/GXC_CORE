#pragma once

// A real blockchain for the tests that need one.
//
// Fraud detection and the reversal pipeline are not pure functions: they read
// the chain through Blockchain::getTransaction, getDescendantTransactions,
// getTransactionBlockHeight and getBalance. Those are not virtual, so there is
// no seam to substitute a fake at, and faking them by hand would prove only
// that the fake behaves as written. So these suites mine a real chain into a
// real LevelDB and let the production queries walk it.
//
// Building it is the expensive part (proof of work on every block, plus the
// six-confirmation coinbase maturity rule), so the chain is built once per
// process and shared. It carries several independent theft cases, because
// executing a reversal mutates chain state -- a test that reverses must not
// disturb one that inspects.

#include "../include/Block.h"
#include "../include/Config.h"
#include "../include/Crypto.h"
#include "../include/Database.h"
#include "../include/blockchain.h"
#include "../include/transaction.h"

#include <signal.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace gxctest {

/** One theft scenario: victim -> thief -> mule, each step confirmed. */
struct TheftCase {
    Transaction funding; // Coinbase the victim legitimately owns
    Transaction theft;   // The transaction the victim reports as stolen
    Transaction hop;     // Thief layering the proceeds on to a mule
};

class TestChain {
public:
    Blockchain chain;

    Crypto::KeyPair victimKeys;
    Crypto::KeyPair thiefKeys;
    Crypto::KeyPair muleKeys;
    Crypto::KeyPair minerKeys;

    std::string victim;
    std::string thief;
    std::string mule;
    std::string miner;

    /** Independent cases, so a destructive test can claim one of its own. */
    std::vector<TheftCase> cases;

    /** A theft whose proceeds sat untouched for over a week before moving. */
    TheftCase dormant;

    /**
     * Two further cases whose hops are consumed by `reAggregation`. They are
     * kept separate from `cases` so that recombining them does not drain the
     * mule, whose balance the proof tests measure against.
     */
    std::vector<TheftCase> reAggSources;

    /**
     * A theft followed by twelve successive hops, for the propagation bound:
     * longer than the ten-hop default so the cut-off is observable.
     */
    Transaction longChainTheft;
    std::vector<Transaction> longChainHops;

    /** A spend splitting tainted funds across many recipients (smurfing). */
    Transaction fanOut;
    std::vector<std::string> fanOutRecipients;

    /** Two tainted outputs recombined into one transaction (layering). */
    Transaction reAggregation;

    TestChain() : directory(dataDir()) {
        // A fresh database, private to this process. CTest registers each
        // suite as its own test and may run them in parallel, so the path
        // carries the pid: two processes must not open one LevelDB, and
        // neither may inherit the previous run's reversal marks.
        const std::string& dir = directory;
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        removeStaleDirectories();

        Config::setDefaults();
        Config::set("testnet", "true");
        Config::set("data_dir", dir);

        // The database refuses to open a path without "testnet" in it while in
        // testnet mode, which is why dataDir() spells it out.
        if (!Database::initialize(dir)) {
            throw std::runtime_error("test chain: could not open database at " + dir);
        }
        if (!chain.initialize()) {
            throw std::runtime_error("test chain: could not initialize blockchain");
        }

        victimKeys = Crypto::generateKeyPair();
        thiefKeys = Crypto::generateKeyPair();
        muleKeys = Crypto::generateKeyPair();
        minerKeys = Crypto::generateKeyPair();
        victim = Crypto::generateAddress(victimKeys.publicKey, true);
        thief = Crypto::generateAddress(thiefKeys.publicKey, true);
        mule = Crypto::generateAddress(muleKeys.publicKey, true);
        miner = Crypto::generateAddress(minerKeys.publicKey, true);

        build();
    }

    TestChain(const TestChain&) = delete;
    TestChain& operator=(const TestChain&) = delete;

    /** Mine one block: coinbase to `to`, plus `extra` spends. */
    void mine(const std::string& to,
              const Crypto::KeyPair& keys,
              const std::vector<Transaction>& extra = {}) {
        Block block(static_cast<uint32_t>(chain.getHeight()),
                    chain.getLatestBlock().getHash(),
                    BlockType::POW_SHA256);
        block.setMinerAddress(to);
        block.setMinerPublicKey(keys.publicKey);

        Transaction coinbase(to, kReward);
        block.addTransactionUnchecked(coinbase);
        for (const auto& tx : extra) {
            block.addTransactionUnchecked(tx);
        }

        if (!block.mineBlock(chain.getDifficulty(), kAttemptBudget)) {
            throw std::runtime_error("test chain: no proof of work found at height " +
                                     std::to_string(chain.getHeight()));
        }
        if (!chain.addBlock(block)) {
            throw std::runtime_error("test chain: block rejected at height " +
                                     std::to_string(chain.getHeight()));
        }
    }

    /** The coinbase of the block at `index`. */
    Transaction coinbaseAt(size_t index) const {
        return chain.getBlock(index).getTransactions()[0];
    }

    /**
     * A signed spend of `funding`'s first output, paying the remainder to `to`.
     * `timestampOffset` shifts the transaction's own clock, for the rules that
     * key off how long funds were held.
     */
    Transaction spend(const Crypto::KeyPair& fromKeys,
                      const std::string& from,
                      const std::string& to,
                      const Transaction& funding,
                      double fee = kFee,
                      int64_t timestampOffset = 0) const {
        const double amount = funding.getOutputs()[0].amount;
        return spendTo(fromKeys, from, {{to, amount - fee}}, funding, fee, timestampOffset);
    }

    /** A signed spend of `funding` paying each (address, amount) in `payouts`. */
    Transaction spendTo(const Crypto::KeyPair& fromKeys,
                        const std::string& from,
                        const std::vector<std::pair<std::string, double>>& payouts,
                        const Transaction& funding,
                        double fee = kFee,
                        int64_t timestampOffset = 0) const {
        const double amount = funding.getOutputs()[0].amount;

        TransactionInput input;
        input.txHash = funding.getHash();
        input.outputIndex = 0;
        input.amount = amount;

        std::vector<TransactionOutput> outputs;
        for (const auto& payout : payouts) {
            TransactionOutput output;
            output.address = payout.first;
            output.amount = payout.second;
            output.script =
                "OP_DUP OP_HASH160 " + payout.first + " OP_EQUALVERIFY OP_CHECKSIG";
            outputs.push_back(output);
        }

        Transaction tx(std::vector<TransactionInput>{input}, outputs, funding.getHash());
        tx.setFee(fee);
        tx.setReferencedAmount(amount);
        tx.setSenderAddress(from);
        tx.setReceiverAddress(payouts.front().first);
        if (timestampOffset != 0) {
            tx.setTimestamp(static_cast<uint64_t>(
                static_cast<int64_t>(tx.getTimestamp()) + timestampOffset));
        }
        tx.signInputs(fromKeys.privateKey);
        return tx;
    }

    /** A spend combining several funded outputs into one payout. */
    Transaction combine(const Crypto::KeyPair& fromKeys,
                        const std::string& from,
                        const std::string& to,
                        const std::vector<Transaction>& fundings,
                        double fee = kFee) const {
        std::vector<TransactionInput> inputs;
        double total = 0.0;
        for (const auto& funding : fundings) {
            TransactionInput input;
            input.txHash = funding.getHash();
            input.outputIndex = 0;
            input.amount = funding.getOutputs()[0].amount;
            total += input.amount;
            inputs.push_back(input);
        }

        TransactionOutput output;
        output.address = to;
        output.amount = total - fee;
        output.script = "OP_DUP OP_HASH160 " + to + " OP_EQUALVERIFY OP_CHECKSIG";

        Transaction tx(inputs, {output}, fundings.front().getHash());
        tx.setFee(fee);
        tx.setReferencedAmount(inputs.front().amount);
        tx.setSenderAddress(from);
        tx.setReceiverAddress(to);
        tx.signInputs(fromKeys.privateKey);
        return tx;
    }

    static constexpr double kReward = 50.0;
    static constexpr double kFee = 0.01;
    static constexpr uint64_t kAttemptBudget = 2000000;

    /** Blocks a coinbase must wait before it can be spent. */
    static constexpr int kCoinbaseMaturity = 6;

    /** FraudDetection's DORMANCY_PERIOD: seven days. */
    static constexpr int64_t kDormancyPeriod = 604800;

    /** propagateTaint's default maxHops. */
    static constexpr int kDefaultMaxHops = 10;

    /** Hops in the long layering chain: two past the default bound. */
    static constexpr int kLongChainHops = 12;

private:
    std::string directory;

    /** Prefix shared by every run's database directory. */
    static const char* dirPrefix() { return "gxc-testnet-fraud-suite-"; }

    /**
     * Drop databases left by runs that are no longer going.
     *
     * The fixture is deliberately never destroyed -- see testChain() -- so it
     * cannot clean up after itself on the way out. Clearing other runs'
     * directories on the way in bounds the temp space instead, and skipping
     * live pids keeps a parallel CTest run's siblings intact.
     */
    void removeStaleDirectories() const {
        std::error_code ec;
        const auto parent = std::filesystem::temp_directory_path();
        for (std::filesystem::directory_iterator it(parent, ec), end; it != end;
             it.increment(ec)) {
            if (ec) {
                return;
            }
            const std::string name = it->path().filename().string();
            if (name.rfind(dirPrefix(), 0) != 0 || it->path().string() == directory) {
                continue;
            }

            const std::string pid = name.substr(std::strlen(dirPrefix()));
            if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos) {
                continue;
            }
            // Still running: another suite of this same CTest invocation.
            if (::kill(static_cast<pid_t>(std::stol(pid)), 0) == 0) {
                continue;
            }

            std::error_code removeError;
            std::filesystem::remove_all(it->path(), removeError);
        }
    }

    static std::string dataDir() {
        // "testnet" has to appear in the path: the database refuses to open a
        // store whose name does not say so while the node is in testnet mode,
        // which is the guard that keeps test runs away from mainnet data.
        const std::string name =
            std::string(dirPrefix()) + std::to_string(static_cast<long>(::getpid()));
        return (std::filesystem::temp_directory_path() / name).string();
    }

    void build() {
        // Eight coinbases to the victim, one per independent scenario.
        const size_t firstFunding = chain.getHeight();
        for (int i = 0; i < 8; i++) {
            mine(victim, victimKeys);
        }

        // One padding run matures all five at once.
        for (int i = 0; i < kCoinbaseMaturity; i++) {
            mine(miner, minerKeys);
        }

        // Two complete victim -> thief -> mule cases.
        for (int i = 0; i < 2; i++) {
            TheftCase c;
            c.funding = coinbaseAt(firstFunding + static_cast<size_t>(i));
            c.theft = spend(victimKeys, victim, thief, c.funding);
            mine(miner, minerKeys, {c.theft});
            c.hop = spend(thiefKeys, thief, mule, c.theft);
            mine(miner, minerKeys, {c.hop});
            cases.push_back(c);
        }

        // A case the thief still holds: no hop, so the current holder of the
        // tainted funds is the thief himself.
        {
            TheftCase c;
            c.funding = coinbaseAt(firstFunding + 2);
            c.theft = spend(victimKeys, victim, thief, c.funding);
            mine(miner, minerKeys, {c.theft});
            cases.push_back(c);
        }

        // A case where the thief held the proceeds for eight days. The theft
        // is backdated rather than the hop post-dated, so no transaction
        // claims a timestamp in the future.
        {
            dormant.funding = coinbaseAt(firstFunding + 3);
            dormant.theft = spend(victimKeys, victim, thief, dormant.funding, kFee,
                                  -(kDormancyPeriod + 86400));
            mine(miner, minerKeys, {dormant.theft});
            dormant.hop = spend(thiefKeys, thief, mule, dormant.theft);
            mine(miner, minerKeys, {dormant.hop});
        }

        // Two more cases whose proceeds the mule later recombines. Their hops
        // are spent, so they must not be the cases the proof tests use.
        for (int i = 0; i < 2; i++) {
            TheftCase c;
            c.funding = coinbaseAt(firstFunding + 5 + static_cast<size_t>(i));
            c.theft = spend(victimKeys, victim, thief, c.funding);
            mine(miner, minerKeys, {c.theft});
            c.hop = spend(thiefKeys, thief, mule, c.theft);
            mine(miner, minerKeys, {c.hop});
            reAggSources.push_back(c);
        }

        // Tainted funds split across six recipients, one more than FAN_OUT_K.
        {
            const Transaction funding = coinbaseAt(firstFunding + 4);
            const Transaction theft = spend(victimKeys, victim, thief, funding);
            mine(miner, minerKeys, {theft});

            std::vector<std::pair<std::string, double>> payouts;
            const double each = (theft.getOutputs()[0].amount - kFee) / 6.0;
            for (int i = 0; i < 6; i++) {
                const auto keys = Crypto::generateKeyPair();
                const std::string address = Crypto::generateAddress(keys.publicKey, true);
                fanOutRecipients.push_back(address);
                payouts.emplace_back(address, each);
            }
            fanOut = spendTo(thiefKeys, thief, payouts, theft);
            mine(miner, minerKeys, {fanOut});

            // Keep the theft reachable: the fan-out's taint descends from it.
            TheftCase c;
            c.funding = funding;
            c.theft = theft;
            cases.push_back(c);
        }

        // The mule recombines the proceeds of the two dedicated cases.
        reAggregation =
            combine(muleKeys, mule, thief, {reAggSources[0].hop, reAggSources[1].hop});
        mine(miner, minerKeys, {reAggregation});

        // A long layering chain, to show propagation stopping at its bound.
        {
            const Transaction funding = coinbaseAt(firstFunding + 7);
            longChainTheft = spend(victimKeys, victim, thief, funding);
            mine(miner, minerKeys, {longChainTheft});

            Crypto::KeyPair holderKeys = thiefKeys;
            std::string holder = thief;
            Transaction previous = longChainTheft;

            for (int i = 0; i < kLongChainHops; i++) {
                const auto nextKeys = Crypto::generateKeyPair();
                const std::string next = Crypto::generateAddress(nextKeys.publicKey, true);

                const Transaction hop = spend(holderKeys, holder, next, previous);
                mine(miner, minerKeys, {hop});

                longChainHops.push_back(hop);
                holderKeys = nextKeys;
                holder = next;
                previous = hop;
            }
        }
    }
};

/**
 * The shared chain, built on first use and never destroyed.
 *
 * The leak is deliberate. A Blockchain torn down during static destruction
 * logs from its own destructor and from each of its members', which means
 * reaching for the logger at a point where the order of teardown across
 * translation units decides whether it is still there. Holding the fixture for
 * the life of the process keeps the suites independent of that ordering; the
 * memory goes back when the process exits either way.
 */
inline TestChain& testChain() {
    static TestChain* const instance = new TestChain();
    return *instance;
}

} // namespace gxctest
