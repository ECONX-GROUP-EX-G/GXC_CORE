// gxc-minedemo -- mine a real chain with every algorithm and audit the result.
//
// This exists to answer three questions concretely, rather than by assertion:
//
//   1. Does mining work for SHA-256, Ethash, and GXHash?
//   2. Does the money balance? Every coin in existence has to trace to a
//      coinbase, and the sum of all spendable outputs plus all fees collected
//      has to equal the sum of all rewards issued -- exactly, not approximately.
//   3. Is each block actually valid -- hash, merkle root, target, work receipt,
//      and Proof of Traceability on the spends?
//
// It runs the real consensus functions. Nothing here is a mock.

#include "../include/Block.h"
#include "../include/Config.h"
#include "../include/Crypto.h"
#include "../include/HashUtils.h"
#include "../include/arith_uint256.h"
#include "../include/transaction.h"

#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

const char* BOLD = "\033[1m";
const char* DIM = "\033[2m";
const char* GREEN = "\033[32m";
const char* RED = "\033[31m";
const char* RESET = "\033[0m";

void heading(const std::string& text) {
    std::cout << "\n" << BOLD << text << RESET << "\n"
              << DIM << std::string(text.size(), '-') << RESET << "\n";
}

void check(bool ok, const std::string& label) {
    std::cout << "  " << (ok ? GREEN : RED) << (ok ? "OK  " : "FAIL") << RESET
              << "  " << label << "\n";
}

std::string gxc(double amount) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(8) << amount;
    return ss.str();
}

// ---------------------------------------------------------------------------
// A minimal in-memory ledger: the UTXO set, plus the accounting we want to audit
// ---------------------------------------------------------------------------

struct Ledger {
    std::map<std::string, TransactionOutput> utxos;   // "txid_index" -> output
    double totalIssued = 0.0;     // every coinbase reward ever paid
    double totalFees = 0.0;       // fees taken out of spends
    uint32_t blocksAccepted = 0;
    bool allValid = true;

    void credit(const Transaction& tx) {
        uint32_t index = 0;
        for (const auto& output : tx.getOutputs()) {
            utxos[tx.getHash() + "_" + std::to_string(index++)] = output;
        }
    }

    void debit(const Transaction& tx) {
        for (const auto& input : tx.getInputs()) {
            utxos.erase(input.txHash + "_" + std::to_string(input.outputIndex));
        }
    }

    double spendable() const {
        double total = 0.0;
        for (const auto& [key, output] : utxos) {
            (void)key;
            total += output.amount;
        }
        return total;
    }

    double balanceOf(const std::string& address) const {
        double total = 0.0;
        for (const auto& [key, output] : utxos) {
            (void)key;
            if (output.address == address) total += output.amount;
        }
        return total;
    }
};

/** The protocol's issuance schedule: R(h) = 50 / 2^floor(h / 1051200). */
double scheduledReward(uint32_t height) {
    const uint32_t HALVING_INTERVAL = 1051200;
    double reward = 50.0;
    for (uint32_t i = 0; i < height / HALVING_INTERVAL; i++) reward /= 2.0;
    return reward;
}

struct AlgoSpec {
    BlockType type;
    const char* name;
    uint64_t attemptBudget;
};

/**
 * Apply every validity rule a receiving node would apply to a block, short of
 * chain context. Returns false on the first failure.
 */
bool validateBlock(const Block& block, bool testnet, std::vector<std::string>& failures) {
    if (!block.hasValidHash())        failures.push_back("header hash does not match contents");
    if (!block.hasValidMerkleRoot())  failures.push_back("merkle root does not match transactions");
    if (!meetsTarget(block.getHash(), block.getDifficulty(), testnet))
        failures.push_back("hash does not meet the declared target");
    if (!block.verifyWorkReceipt())   failures.push_back("work receipt does not verify");

    for (const auto& tx : block.getTransactions()) {
        if (!tx.verifyTransaction()) failures.push_back("transaction " + tx.getHash().substr(0, 12) + " invalid");
        if (!tx.isCoinbaseTransaction() && !tx.verifyTraceabilityFormula())
            failures.push_back("POT failed for " + tx.getHash().substr(0, 12));
    }
    return failures.empty();
}

} // namespace

int main(int argc, char** argv) {
    uint32_t blocksPerAlgorithm = 3;
    if (argc > 1) {
        const int requested = std::atoi(argv[1]);
        if (requested > 0 && requested <= 100) blocksPerAlgorithm = static_cast<uint32_t>(requested);
    }

    // Testnet: a near-maximal proof-of-work limit, so a CPU finds blocks at once.
    Config::setNetworkMode(true);
    const bool testnet = true;
    const double difficulty = 1.0;

    std::cout << BOLD << "\nGXC-CORE mining and ledger audit" << RESET << "\n";
    std::cout << DIM << "network: testnet   difficulty: " << difficulty
              << "   target: " << DifficultyToTarget(difficulty, testnet).GetHex().substr(0, 20)
              << "..." << RESET << "\n";

    // Two participants: a miner who earns rewards, and a recipient who is paid.
    const Crypto::KeyPair minerKeys = Crypto::generateKeyPair();
    const std::string minerAddress = Crypto::generateAddress(minerKeys.publicKey, testnet);
    const Crypto::KeyPair aliceKeys = Crypto::generateKeyPair();
    const std::string aliceAddress = Crypto::generateAddress(aliceKeys.publicKey, testnet);

    std::cout << DIM << "miner:     " << minerAddress << RESET << "\n";
    std::cout << DIM << "recipient: " << aliceAddress << RESET << "\n";

    const AlgoSpec algorithms[] = {
        {BlockType::POW_SHA256, "SHA-256",  5000000},
        {BlockType::POW_ETHASH, "Ethash",    500000},
        {BlockType::POW_GXHASH, "GXHash",     20000},
    };

    Ledger ledger;
    std::vector<Block> chain;
    std::string previousHash = std::string(64, '0');   // genesis parent
    uint32_t height = 0;

    // -----------------------------------------------------------------------
    // Mine
    // -----------------------------------------------------------------------

    for (const AlgoSpec& algo : algorithms) {
        heading(std::string("Mining with ") + algo.name);

        double algoSeconds = 0.0;
        uint64_t algoNonces = 0;

        for (uint32_t i = 0; i < blocksPerAlgorithm; i++) {
            Block block(height, previousHash, algo.type);
            block.setMinerAddress(minerAddress);
            block.setMinerPublicKey(minerKeys.publicKey);

            const double reward = scheduledReward(height);

            // Coinbase pays the scheduled reward. From the second block onward
            // the miner also spends an earlier reward to Alice, so the audit
            // has real spends to reconcile and POT has a chain to verify.
            Transaction coinbase(minerAddress, reward);
            block.addTransactionUnchecked(coinbase);

            Transaction spend;
            bool hasSpend = false;
            if (height > 0) {
                // Spend the coinbase of the previous block.
                const Transaction& parent = chain.back().getTransactions()[0];
                const double parentAmount = parent.getOutputs()[0].amount;
                const double fee = 0.01;
                const double payout = parentAmount - fee;

                TransactionInput input;
                input.txHash = parent.getHash();
                input.outputIndex = 0;
                input.amount = parentAmount;

                TransactionOutput output;
                output.address = aliceAddress;
                output.amount = payout;
                output.script = "OP_DUP OP_HASH160 " + aliceAddress + " OP_EQUALVERIFY OP_CHECKSIG";

                spend = Transaction({input}, {output}, parent.getHash());
                spend.setFee(fee);
                spend.setReferencedAmount(parentAmount);
                spend.signInputs(minerKeys.privateKey);

                block.addTransactionUnchecked(spend);
                hasSpend = true;
            }

            const auto started = std::chrono::steady_clock::now();
            const bool found = block.mineBlock(difficulty, algo.attemptBudget);
            const double seconds =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

            if (!found) {
                std::cout << "  " << RED << "FAIL" << RESET
                          << "  height " << height << ": no solution within "
                          << algo.attemptBudget << " attempts\n";
                ledger.allValid = false;
                break;
            }

            algoSeconds += seconds;
            algoNonces += block.getNonce() + 1;

            // Validate exactly as a peer would.
            std::vector<std::string> failures;
            const bool valid = validateBlock(block, testnet, failures);
            if (!valid) {
                ledger.allValid = false;
                for (const auto& f : failures) {
                    std::cout << "  " << RED << "FAIL" << RESET << "  height " << height << ": " << f << "\n";
                }
                break;
            }

            // Also confirm it survives a round trip over the wire.
            const Block relayed = Block::deserialize(block.serialize());
            std::vector<std::string> relayFailures;
            if (relayed.getHash() != block.getHash() ||
                !validateBlock(relayed, testnet, relayFailures)) {
                std::cout << "  " << RED << "FAIL" << RESET
                          << "  height " << height << ": block does not survive serialization\n";
                ledger.allValid = false;
                break;
            }

            // Accept into the ledger.
            if (hasSpend) {
                ledger.debit(spend);
                ledger.credit(spend);
                ledger.totalFees += spend.getFee();
            }
            ledger.credit(block.getTransactions()[0]);
            ledger.totalIssued += reward;
            ledger.blocksAccepted++;

            std::cout << "  " << GREEN << "OK  " << RESET
                      << "height " << std::setw(2) << height
                      << "  nonce " << std::setw(7) << block.getNonce()
                      << "  " << std::fixed << std::setprecision(3) << std::setw(7) << seconds << "s"
                      << "  reward " << gxc(reward)
                      << "  " << DIM << block.getHash().substr(0, 16) << "..." << RESET << "\n";

            previousHash = block.getHash();
            chain.push_back(block);
            height++;
        }

        if (algoSeconds > 0.0 && algoNonces > 0) {
            // Reporting H/s here would be misleading: at the testnet target
            // nearly every nonce wins, so the sample is one or two hashes and
            // the rate is noise. Cost per hash is the number that means
            // something -- it is what separates a SHA-256 ASIC from a
            // memory-hard function, and it holds at any difficulty.
            std::cout << DIM << "       " << algoNonces << " hashes, "
                      << std::fixed << std::setprecision(2)
                      << (algoSeconds * 1000.0 / static_cast<double>(algoNonces))
                      << " ms per hash" << RESET << "\n";
        }
    }

    // -----------------------------------------------------------------------
    // Chain integrity
    // -----------------------------------------------------------------------

    heading("Chain integrity");

    bool linked = true;
    for (size_t i = 1; i < chain.size(); i++) {
        if (chain[i].getPreviousHash() != chain[i - 1].getHash()) linked = false;
        if (chain[i].getIndex() != chain[i - 1].getIndex() + 1) linked = false;
    }
    check(linked, "every block links to its parent, heights strictly increase");

    bool receiptsBound = true;
    for (const Block& block : chain) {
        const Transaction& coinbase = block.getTransactions()[0];
        if (coinbase.getWorkReceiptHash() != block.getWorkReceiptHash()) receiptsBound = false;
        if (coinbase.getWorkReceiptHash() != block.computeWorkReceipt()) receiptsBound = false;
        if (coinbase.getBlockHeight() != block.getIndex()) receiptsBound = false;
    }
    check(receiptsBound, "every coinbase carries its block's work receipt and height");

    // Walk each spend back to the coinbase it descends from.
    bool traceable = true;
    size_t spendsTraced = 0;
    std::map<std::string, Transaction> byHash;
    for (const Block& block : chain) {
        for (const auto& tx : block.getTransactions()) byHash[tx.getHash()] = tx;
    }
    for (const Block& block : chain) {
        for (const auto& tx : block.getTransactions()) {
            if (tx.isCoinbaseTransaction()) continue;
            // Follow prevTxHash until a coinbase is reached.
            std::string cursor = tx.getPrevTxHash();
            size_t hops = 0;
            while (byHash.count(cursor) && !byHash[cursor].isCoinbaseTransaction() && hops < 100) {
                cursor = byHash[cursor].getPrevTxHash();
                hops++;
            }
            if (!byHash.count(cursor) || !byHash[cursor].isCoinbaseTransaction()) traceable = false;
            spendsTraced++;
        }
    }
    check(traceable, "all " + std::to_string(spendsTraced) +
                     " spends trace back to a coinbase via prevTxHash");

    bool algorithmsDistinct = true;
    std::map<int, int> perType;
    for (const Block& block : chain) perType[static_cast<int>(block.getBlockType())]++;
    for (const AlgoSpec& algo : algorithms) {
        if (perType[static_cast<int>(algo.type)] == 0) algorithmsDistinct = false;
    }
    check(algorithmsDistinct, "all three algorithms produced accepted blocks");

    // -----------------------------------------------------------------------
    // The balance sheet
    // -----------------------------------------------------------------------

    heading("Balance sheet");

    const double spendable = ledger.spendable();
    const double minerBalance = ledger.balanceOf(minerAddress);
    const double aliceBalance = ledger.balanceOf(aliceAddress);

    std::cout << "  Blocks accepted              " << std::setw(20) << ledger.blocksAccepted << "\n";
    std::cout << "  Rewards issued (coinbases)   " << std::setw(20) << gxc(ledger.totalIssued) << " GXC\n";
    std::cout << "  Fees collected from spends   " << std::setw(20) << gxc(ledger.totalFees) << " GXC\n";
    std::cout << DIM << "  " << std::string(50, '-') << RESET << "\n";
    std::cout << "  Miner spendable              " << std::setw(20) << gxc(minerBalance) << " GXC\n";
    std::cout << "  Recipient spendable          " << std::setw(20) << gxc(aliceBalance) << " GXC\n";
    std::cout << "  Total spendable (UTXO set)   " << std::setw(20) << gxc(spendable) << " GXC\n";
    std::cout << "  UTXO count                   " << std::setw(20) << ledger.utxos.size() << "\n";

    heading("Reconciliation");

    // Fees are deducted from spends and are not re-credited anywhere in this
    // demo (on-chain they go to the miner and the system pool), so the identity
    // that must hold exactly is:
    //
    //     rewards issued  ==  spendable outputs  +  fees withheld
    const double expected = ledger.totalIssued;
    const double accounted = spendable + ledger.totalFees;
    const double drift = std::fabs(expected - accounted);

    std::cout << "  issued            " << std::setw(20) << gxc(expected) << " GXC\n";
    std::cout << "  spendable + fees  " << std::setw(20) << gxc(accounted) << " GXC\n";
    std::cout << "  difference        " << std::setw(20) << gxc(drift) << " GXC\n\n";

    const bool balances = drift < 1e-9;
    check(balances, "the ledger balances: no coin created or destroyed outside a coinbase");

    bool scheduleCorrect = true;
    for (const Block& block : chain) {
        const double paid = block.getTransactions()[0].getOutputs()[0].amount;
        if (std::fabs(paid - scheduledReward(block.getIndex())) > 1e-9) scheduleCorrect = false;
    }
    check(scheduleCorrect, "every reward matches the issuance schedule R(h) = 50 / 2^floor(h/1051200)");

    const bool supplyCapped = ledger.totalIssued <= 31000000.0;
    check(supplyCapped, "total issued stays within the 31,000,000 GXC cap");

    // -----------------------------------------------------------------------

    const bool pass = ledger.allValid && linked && receiptsBound && traceable &&
                      algorithmsDistinct && balances && scheduleCorrect && supplyCapped;

    std::cout << "\n" << BOLD << (pass ? GREEN : RED)
              << (pass ? "PASS" : "FAIL") << RESET << BOLD
              << " -- " << ledger.blocksAccepted << " blocks mined across "
              << (sizeof(algorithms) / sizeof(algorithms[0])) << " algorithms, "
              << spendsTraced << " spends traced, books balance to "
              << gxc(drift) << " GXC" << RESET << "\n\n";

    return pass ? 0 : 1;
}
