# GXC-CORE API Reference

## Overview

GXC-CORE exposes three API interfaces:

| Interface | Default Port | Protocol | Purpose |
|-----------|-------------|----------|---------|
| JSON-RPC | 8332 (mainnet) / 18332 (testnet) | JSON-RPC 2.0 | Node control, wallet operations |
| REST | 8080 | HTTP/HTTPS | Block explorer, public queries |
| WebSocket | 8081 | WS | Real-time event streaming |

---

## JSON-RPC API

### Connection

```bash
curl -X POST http://localhost:8332/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}'
```

### Blockchain Methods

#### `getblockchaininfo`
Returns detailed blockchain state information.

**Parameters:** None

**Response:**
```json
{
  "chain": "main",
  "blocks": 12345,
  "height": 12345,
  "bestblockhash": "abc123...",
  "difficulty": 1000.0,
  "block_reward": 50.0,
  "mediantime": 1709600000,
  "verificationprogress": 1.0,
  "pruned": false
}
```

#### `getblockcount`
Returns the current block height.

**Parameters:** None

**Response:** `12345` (integer)

#### `getbestblockhash`
Returns the hash of the latest block.

**Parameters:** None

**Response:** `"abc123..."` (string)

#### `getdifficulty`
Returns the current mining difficulty.

**Parameters:** None

**Response:** `1000.0` (number)

#### `getblock`
Returns block data by height or hash.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string/int | Block hash or height (`"latest"` for tip) |
| 1 | bool | Verbose output (optional, default: true) |

**Aliases:** `getblockbynumber`, `gxc_getBlockByNumber`

**Response:**
```json
{
  "hash": "abc123...",
  "height": 12345,
  "previousblockhash": "def456...",
  "merkleroot": "789...",
  "timestamp": 1709600000,
  "difficulty": 1000.0,
  "nonce": 42,
  "type": "POW_SHA256",
  "transactions": [...]
}
```

#### `getlatestblock`
Returns the most recent block.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | bool | Verbose output (optional) |

**Aliases:** `gxc_getLatestBlock`

#### `getblockhash`
Returns the block hash at a given height.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | int | Block height |

**Response:** `"abc123..."` (string)

---

### Transaction Methods

#### `gettransaction`
Returns transaction details by hash.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Transaction hash |

**Aliases:** `gxc_getTransaction`, `gettx`

**Response:**
```json
{
  "hash": "abc123...",
  "type": "NORMAL",
  "sender": "GXC...",
  "receiver": "GXC...",
  "amount": 10.0,
  "fee": 0.001,
  "timestamp": 1709600000,
  "inputs": [...],
  "outputs": [...],
  "prevTxHash": "def456...",
  "referencedAmount": 50.0
}
```

#### `getrawtransaction`
Returns raw transaction data.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Transaction hash |

#### `sendrawtransaction`
Submits a signed transaction to the network.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Signed transaction hex |

**Response:** Transaction hash (string)

#### `listtransactions`
Returns transactions for an address.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Address |
| 1 | int | Count (optional, default: 10) |

**Aliases:** `getaddresstransactions`, `getaddresshistory`, `searchrawtransactions`

#### `getaddresstxids`
Returns only transaction IDs for an address.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Address |

#### `getblocktransactions`
Returns all transactions in a block.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | int | Block height |

**Aliases:** `getblocktxs`

---

### Wallet Methods

#### `getbalance`
Returns the balance for the node wallet or a specified address.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Address (optional, defaults to node wallet) |

**Response:** `100.5` (number, in GXC)

#### `getnewaddress`
Generates a new address in the node wallet.

**Parameters:** None

**Response:** `"GXC..."` (string)

#### `sendtoaddress`
Creates and broadcasts a transaction.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Recipient address |
| 1 | number | Amount in GXC |
| 2 | number | Fee (optional) |

**Response:** Transaction hash (string)

#### `validateaddress`
Validates a GXC address format.

**Parameters:**
| # | Type | Description |
|---|------|-------------|
| 0 | string | Address to validate |

**Response:**
```json
{
  "isvalid": true,
  "address": "GXC...",
  "ismine": false
}
```

---

### Mining Methods

#### `getmininginfo`
Returns current mining state.

**Parameters:** None

**Response:**
```json
{
  "blocks": 12345,
  "difficulty": 1000.0,
  "networkhashps": 1500000.0,
  "algorithm": "SHA256",
  "mining": true
}
```

---

### Staking Methods

#### `getstakinginfo`
Returns staking state for the node.

**Parameters:** None

**Response:**
```json
{
  "staking": true,
  "stake_amount": 500.0,
  "weight": 125.0,
  "expected_time": 3600,
  "rewards_earned": 2.5
}
```

---

## REST API

### Health & Status

#### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "GXC Blockchain REST API"
}
```

---

### Blockchain Data

#### `GET /api/v1/blockchain/info`
Returns full blockchain state.

#### `GET /api/v1/block/{height}`
Returns block by height.

**Parameters:**
| Name | In | Type | Description |
|------|-----|------|-------------|
| height | path | integer | Block height |

#### `GET /api/v1/blocks`
Returns recent blocks (paginated).

#### `GET /api/v1/transaction/{hash}`
Returns transaction by hash.

**Parameters:**
| Name | In | Type | Description |
|------|-----|------|-------------|
| hash | path | string | Transaction hash |

#### `POST /api/v1/transactions`
Submit a new transaction.

**Body:**
```json
{
  "from": "GXC...",
  "to": "GXC...",
  "amount": 10.0,
  "fee": 0.001,
  "signature": "..."
}
```

---

### Address Queries

#### `GET /api/v1/address/{address}/balance`
Returns address balance.

#### `GET /api/v1/address/{address}/transactions`
Returns transactions for an address.

---

### Traceability

#### `GET /api/v1/trace/{txHash}`
Returns the Proof of Traceability chain for a transaction, including taint scores and ancestry path.

**Response:**
```json
{
  "txHash": "abc123...",
  "taintScore": 0.45,
  "sourceTransaction": "stolen_tx_hash...",
  "ancestry": ["tx1", "tx2", "tx3"],
  "alerts": [
    {
      "level": "HIGH",
      "rule": "VELOCITY_ANOMALY",
      "description": "Rapid fund movement detected"
    }
  ]
}
```

---

### Mining Info

#### `GET /api/v1/mining/info`
Returns mining statistics.

### Network

#### `GET /api/v1/network/peers`
Returns connected peer list.

### Statistics

#### `GET /api/v1/stats`
Returns aggregate network statistics.

---

## Fraud Detection Endpoints

### Public Endpoints

#### `GET /api/fraud/status`
Returns fraud detection system status.

**Response:**
```json
{
  "status": "active",
  "algorithms": ["velocity", "amount", "pattern", "taint", "ai_sentinel"],
  "fraud_detection_enabled": true
}
```

#### `POST /api/fraud/report-stolen`
Report stolen funds for taint tracking.

**Body:**
```json
{
  "txHash": "abc123...",
  "description": "Funds stolen via phishing",
  "reporter": "GXC..."
}
```

#### `GET /api/fraud/check-transaction/{txHash}`
Check taint score for a transaction.

**Response:**
```json
{
  "txHash": "abc123...",
  "tainted": true,
  "taintScore": 0.75,
  "alerts": [...]
}
```

#### `GET /api/fraud/check-address/{address}`
Check if an address is flagged or has fraud alerts.

---

### Admin Endpoints

#### `POST /api/admin/login`
Authenticate as an admin user.

**Body:**
```json
{
  "username": "admin",
  "password": "..."
}
```

#### `GET /api/admin/stats`
Returns admin dashboard statistics (blockchain height, flagged transactions).

---

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8081');
```

### Event Types

| Event | Description |
|-------|-------------|
| `new_block` | Emitted when a new block is added to the chain |
| `new_transaction` | Emitted when a transaction enters the mempool |
| `network_stats` | Periodic network health update |

### Message Format

```json
{
  "event": "new_block",
  "data": {
    "hash": "abc123...",
    "height": 12346,
    "type": "POW_SHA256",
    "transactions": 5,
    "timestamp": 1709600600
  }
}
```

---

## Stratum Mining Protocol

### Connection

```
stratum+tcp://localhost:{stratum_port}
```

### Methods

| Method | Description |
|--------|-------------|
| `mining.subscribe` | Subscribe to mining notifications |
| `mining.authorize` | Authenticate worker |
| `mining.submit` | Submit a share |
| `mining.notify` | New work notification (server-push) |

---

## Error Codes

### JSON-RPC Errors

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Missing required fields |
| -32601 | Method not found | Unknown RPC method |
| -32602 | Invalid params | Wrong parameter types or count |
| -32603 | Internal error | Server-side failure |
| -1 | Wallet error | Insufficient funds or signing failure |
| -5 | Invalid address | Malformed GXC address |
| -6 | Insufficient funds | Balance too low for transaction |
| -8 | Invalid parameter | Parameter out of valid range |

### REST HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request (invalid parameters) |
| 401 | Unauthorized (admin endpoints) |
| 404 | Endpoint or resource not found |
| 500 | Internal server error |
| 503 | Service unavailable |

---

## Configuration

API settings in `gxc.conf`:

```ini
# JSON-RPC
rpc_port=8332          # RPC listen port
rpc_bind=127.0.0.1     # Bind address (default: localhost only)
rpc_threads=4           # Worker threads

# REST API
rest_port=8080          # REST listen port
rest_enabled=true       # Enable REST API

# WebSocket
ws_port=8081            # WebSocket listen port
ws_enabled=true         # Enable WebSocket

# Mining (Stratum)
stratum_enabled=false   # Enable Stratum server
stratum_port=3333       # Stratum listen port
```
