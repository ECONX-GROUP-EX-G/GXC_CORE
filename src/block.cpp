#include "../include/Block.h"
#include "../include/HashUtils.h"
#include "../include/Config.h"
#include "../include/Crypto.h"
#include <iomanip>
#include <sstream>
#include <stdexcept>

Block::Block()
    : index(0), previousHash(""), merkleRoot(""), nonce(0),
      blockType(BlockType::POW_SHA256), minerAddress(""), validatorAddress(""),
      difficulty(0), blockReward(0.0), feeBurnRate(0.0),
      chainWork("0000000000000000000000000000000000000000000000000000000000000000"),
      nBits(0x1d00ffff) {
    timestamp = std::time(nullptr);
    hash = calculateHash();
}

Block::Block(uint32_t indexIn, const std::string& previousHashIn, BlockType type)
    : index(indexIn), previousHash(previousHashIn), merkleRoot(""), nonce(0),
      blockType(type), minerAddress(""), validatorAddress(""),
      difficulty(0), blockReward(0.0), feeBurnRate(0.0),
      chainWork("0000000000000000000000000000000000000000000000000000000000000000"),
      nBits(0x1d00ffff) {
    timestamp = std::time(nullptr);
    hash = calculateHash();
}

std::string Block::calculateHash() const {
    std::stringstream ss;
    ss << index << previousHash << timestamp << merkleRoot << nonce;
    
    if (blockType == BlockType::POW_SHA256) {
        return sha256d(ss.str());
    } else if (blockType == BlockType::POW_ETHASH) {
        return ethash(ss.str(), nonce);
    } else if (blockType == BlockType::POW_GXHASH) {
        return gxhash(ss.str(), nonce);
    } else {
        // For PoS blocks, we just use SHA-256 for the hash
        return sha256(ss.str());
    }
}

bool Block::mineBlock(double difficultyIn, uint64_t maxAttempts) {
    difficulty = difficultyIn;

    // PoS blocks are not mined; they are signed by the selected validator.
    if (blockType != BlockType::POW_SHA256 && blockType != BlockType::POW_ETHASH &&
        blockType != BlockType::POW_GXHASH) {
        return false;
    }

    // The merkle root is part of the hashed header, so it has to be fixed
    // before the search starts.
    calculateMerkleRoot();

    const bool testnet = Config::isTestnet();

    hash = calculateHash();
    for (uint64_t attempt = 0; attempt < maxAttempts; attempt++) {
        if (meetsTarget(hash, difficulty, testnet)) {
            // The work receipt binds the reward to this specific solution, so it
            // can only be computed once the winning nonce is known.
            workReceiptHash = computeWorkReceipt();
            updateTransactionWorkReceipts(workReceiptHash);
            return true;
        }
        nonce++;
        hash = calculateHash();
    }

    // Exhausted the attempt budget without a solution. The caller can adjust the
    // block (new timestamp, different extranonce) and try again.
    return false;
}

std::string Block::computeWorkReceipt() const {
    // WorkReceipt = H(prev_hash || merkle_root || nonce || miner_pubkey || difficulty || timestamp)
    // This proves: which block was extended, what transactions, who did work, under what difficulty, when
    std::stringstream ss;
    ss << previousHash 
       << merkleRoot 
       << nonce 
       << minerPublicKey 
       << difficulty 
       << timestamp;
    
    return sha256(ss.str());
}

bool Block::verifyWorkReceipt() const {
    // PoS blocks earn no mining reward, so they carry no work receipt.
    if (blockType == BlockType::POS) {
        return workReceiptHash.empty();
    }

    if (workReceiptHash.empty()) {
        return false;
    }

    // 1. The stored receipt must be the one this header implies. Because the
    //    receipt commits to the nonce and the merkle root, it cannot be
    //    transplanted onto a different block or a different set of transactions.
    if (computeWorkReceipt() != workReceiptHash) {
        return false;
    }

    // 2. The coinbase must carry the same receipt and the block's own height.
    //    This is the link that makes a newly minted reward traceable back to the
    //    proof-of-work that justified minting it.
    for (const auto& tx : transactions) {
        if (!tx.isCoinbaseTransaction()) {
            continue;
        }
        if (tx.getWorkReceiptHash() != workReceiptHash) {
            return false;
        }
        if (tx.getBlockHeight() != index) {
            return false;
        }
    }

    return true;
}

bool Block::hasValidHash() const {
    return !hash.empty() && hash == calculateHash();
}

bool Block::hasValidMerkleRoot() const {
    return merkleRoot == calculateMerkleRoot();
}

bool Block::validateBlock(const std::string& signature) const {
    // Only PoS blocks are validator-signed.
    if (blockType != BlockType::POS) {
        return false;
    }

    // Fall back to the signature stored on the block when none is supplied.
    const std::string& sig = signature.empty() ? validatorSignature : signature;
    if (sig.empty() || validatorAddress.empty()) {
        return false;
    }

    // The signature covers the PoS header commitment, so it cannot be replayed
    // onto a different block.
    return Crypto::verifySignature(calculatePosHash(), sig, minerPublicKey);
}

std::string Block::calculatePowHash() const {
    // The proof-of-work commitment: everything a miner must fix before
    // searching for a nonce.
    std::stringstream ss;
    ss << index << previousHash << merkleRoot << timestamp
       << static_cast<int>(blockType) << difficulty << nonce;
    return sha256d(ss.str());
}

std::string Block::calculatePosHash() const {
    // The proof-of-stake commitment. It deliberately excludes the nonce (there
    // is no search) and includes the validator so a signature is bound to the
    // validator that produced it.
    std::stringstream ss;
    ss << index << previousHash << merkleRoot << timestamp
       << static_cast<int>(blockType) << validatorAddress;
    return sha256d(ss.str());
}

void Block::calculateMerkleRoot() {
    std::vector<std::string> txHashes;
    for (const auto& tx : transactions) {
        txHashes.push_back(tx.getHash());
    }
    
    merkleRoot = ::calculateMerkleRoot(txHashes);
}

std::string Block::calculateMerkleRoot() const {
    std::vector<std::string> txHashes;
    for (const auto& tx : transactions) {
        txHashes.push_back(tx.getHash());
    }
    
    return ::calculateMerkleRoot(txHashes);
}

bool Block::addTransaction(const Transaction& transaction) {
    // Verify the transaction
    if (!transaction.verifyTransaction()) {
        return false;
    }
    
    // Add the transaction to the block
    transactions.push_back(transaction);
    
    // Recalculate the Merkle root
    calculateMerkleRoot();
    
    return true;
}

void Block::addTransactionUnchecked(const Transaction& transaction) {
    // Add transaction without verification (used when submitting pre-validated blocks)
    transactions.push_back(transaction);
}

void Block::updateTransactionWorkReceipts(const std::string& workReceipt) {
    // Update work receipt hash for all transactions (especially coinbase)
    // This is called after the block is fully prepared and work receipt is computed
    for (auto& tx : transactions) {
        if (tx.isCoinbaseTransaction()) {
            tx.setWorkReceiptHash(workReceipt);
            tx.setBlockHeight(index);
        }
    }
}

// --- serialization ---------------------------------------------------------
//
// Blocks travel over the P2P wire and into LevelDB, so the encoding has to
// round-trip exactly and survive hostile input. Every field is length-prefixed
// as "<len>:<bytes>", which keeps nested transaction payloads (themselves
// '|'-delimited) unambiguous and makes truncation detectable.

namespace {

void writeField(std::ostringstream& out, const std::string& value) {
    out << value.size() << ':' << value;
}

void writeField(std::ostringstream& out, uint64_t value) {
    writeField(out, std::to_string(value));
}

void writeField(std::ostringstream& out, double value) {
    std::ostringstream tmp;
    tmp << std::setprecision(17) << value;
    writeField(out, tmp.str());
}

/** Read one length-prefixed field, advancing `pos`. Throws on malformed input. */
std::string readField(const std::string& data, size_t& pos) {
    const size_t colon = data.find(':', pos);
    if (colon == std::string::npos) {
        throw std::runtime_error("Block::deserialize: missing length prefix");
    }

    const std::string lenStr = data.substr(pos, colon - pos);
    if (lenStr.empty() || lenStr.size() > 20) {
        throw std::runtime_error("Block::deserialize: bad length prefix");
    }
    for (char c : lenStr) {
        if (c < '0' || c > '9') {
            throw std::runtime_error("Block::deserialize: non-numeric length prefix");
        }
    }

    const unsigned long long len = std::stoull(lenStr);
    const size_t start = colon + 1;
    // Guard against a declared length that runs past the end of the buffer --
    // this is the check that stops a truncated or malicious frame from reading
    // out of bounds.
    if (len > data.size() - start) {
        throw std::runtime_error("Block::deserialize: field length exceeds payload");
    }

    pos = start + static_cast<size_t>(len);
    return data.substr(start, static_cast<size_t>(len));
}

uint64_t readUint(const std::string& data, size_t& pos) {
    return std::stoull(readField(data, pos));
}

double readDouble(const std::string& data, size_t& pos) {
    return std::stod(readField(data, pos));
}

} // namespace

std::string Block::serialize() const {
    std::ostringstream out;

    writeField(out, static_cast<uint64_t>(index));
    writeField(out, previousHash);
    writeField(out, hash);
    writeField(out, merkleRoot);
    writeField(out, static_cast<uint64_t>(timestamp));
    writeField(out, nonce);
    writeField(out, static_cast<uint64_t>(blockType));
    writeField(out, minerAddress);
    writeField(out, validatorAddress);
    writeField(out, difficulty);
    writeField(out, validatorSignature);
    writeField(out, blockReward);
    writeField(out, feeBurnRate);
    writeField(out, popReference);
    writeField(out, chainWork);
    writeField(out, static_cast<uint64_t>(nBits));
    writeField(out, workReceiptHash);
    writeField(out, minerPublicKey);

    writeField(out, static_cast<uint64_t>(transactions.size()));
    for (const auto& tx : transactions) {
        writeField(out, tx.serialize());
    }

    return out.str();
}

Block Block::deserialize(const std::string& data) {
    Block block;
    size_t pos = 0;

    block.index = static_cast<uint32_t>(readUint(data, pos));
    block.previousHash = readField(data, pos);
    block.hash = readField(data, pos);
    block.merkleRoot = readField(data, pos);
    block.timestamp = static_cast<std::time_t>(readUint(data, pos));
    block.nonce = readUint(data, pos);

    const uint64_t typeValue = readUint(data, pos);
    if (typeValue > static_cast<uint64_t>(BlockType::POS)) {
        throw std::runtime_error("Block::deserialize: unknown block type");
    }
    block.blockType = static_cast<BlockType>(typeValue);

    block.minerAddress = readField(data, pos);
    block.validatorAddress = readField(data, pos);
    block.difficulty = readDouble(data, pos);
    block.validatorSignature = readField(data, pos);
    block.blockReward = readDouble(data, pos);
    block.feeBurnRate = readDouble(data, pos);
    block.popReference = readField(data, pos);
    block.chainWork = readField(data, pos);
    block.nBits = static_cast<uint32_t>(readUint(data, pos));
    block.workReceiptHash = readField(data, pos);
    block.minerPublicKey = readField(data, pos);

    const uint64_t txCount = readUint(data, pos);
    // Each transaction costs at least a few bytes on the wire, so a count that
    // exceeds the remaining payload is necessarily a lie.
    if (txCount > data.size() - pos) {
        throw std::runtime_error("Block::deserialize: implausible transaction count");
    }

    block.transactions.clear();
    block.transactions.reserve(static_cast<size_t>(txCount));
    for (uint64_t i = 0; i < txCount; i++) {
        Transaction tx;
        if (!tx.deserialize(readField(data, pos))) {
            throw std::runtime_error("Block::deserialize: malformed transaction");
        }
        block.transactions.push_back(tx);
    }

    return block;
}
