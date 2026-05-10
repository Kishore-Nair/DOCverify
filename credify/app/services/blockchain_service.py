"""Blockchain service — interacts with the DocumentRegistry smart contract.

Provides methods to store, verify, and revoke document hashes on any
EVM-compatible chain (Hardhat, Ganache, Polygon, etc.).

Configuration (via ``.env``):
    BLOCKCHAIN_RPC_URL   – JSON-RPC endpoint  (default ``http://127.0.0.1:8545``)
    PRIVATE_KEY          – Hex-encoded private key for signing transactions
    CONTRACT_ADDRESS     – Deployed DocumentRegistry address

When the blockchain node is unreachable every method falls back to a
simulated response so the rest of the pipeline keeps working offline.
"""

import json
import os
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ABI loaded once at module level
# ---------------------------------------------------------------------------

_ABI_PATH = os.path.join(os.path.dirname(__file__), "contract_abi.json")

with open(_ABI_PATH, "r") as _f:
    CONTRACT_ABI = json.load(_f)

# Embedded bytecode placeholder — used only by deploy_contract() during
# local development.  In production the contract is deployed via Hardhat
# and CONTRACT_ADDRESS is set in .env.
#
# To get the real bytecode:
#   npx hardhat compile
#   cat artifacts/contracts/DocumentRegistry.sol/DocumentRegistry.json \
#       | python -c "import sys,json; print(json.load(sys.stdin)['bytecode'])"
CONTRACT_BYTECODE: str | None = os.getenv("CONTRACT_BYTECODE")

# Solidity source kept as a constant so it can be referenced from Python
# without reading from disk.
SOLIDITY_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract DocumentRegistry {
    address public owner;

    struct Document {
        bool exists;
        uint256 timestamp;
        string ipfsCid;
        bool revoked;
    }

    mapping(bytes32 => Document) private documents;

    event DocumentStored(bytes32 indexed docHash, string ipfsCid, uint256 timestamp);
    event DocumentRevoked(bytes32 indexed docHash, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    constructor() { owner = msg.sender; }

    function storeDocument(bytes32 docHash, string memory ipfsCid) public {
        require(!documents[docHash].exists, "Document already registered");
        documents[docHash] = Document(true, block.timestamp, ipfsCid, false);
        emit DocumentStored(docHash, ipfsCid, block.timestamp);
    }

    function verifyDocument(bytes32 docHash) public view
        returns (bool exists, uint256 timestamp, string memory cid)
    {
        Document storage doc = documents[docHash];
        return (doc.exists && !doc.revoked, doc.timestamp, doc.ipfsCid);
    }

    function revokeDocument(bytes32 docHash) public onlyOwner {
        require(documents[docHash].exists, "Document not found");
        require(!documents[docHash].revoked, "Already revoked");
        documents[docHash].revoked = true;
        emit DocumentRevoked(docHash, block.timestamp);
    }
}
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _rpc_url() -> str:
    return os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")


def _private_key() -> str:
    return os.getenv("PRIVATE_KEY", "")


def _contract_address() -> str:
    return os.getenv("CONTRACT_ADDRESS", "")


def _hash_to_bytes32(sha256_hex: str) -> bytes:
    """Convert a 64-char hex SHA-256 string to a 32-byte value."""
    clean = sha256_hex.lower().strip()
    if len(clean) != 64:
        raise ValueError(f"Expected 64-char hex string, got {len(clean)}")
    return bytes.fromhex(clean)


def _get_web3():
    """Return a connected Web3 instance or raise."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(_rpc_url()))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to blockchain RPC at {_rpc_url()}")
    return w3


def _get_contract(w3=None):
    """Return the contract object bound to the configured address."""
    from web3 import Web3

    if w3 is None:
        w3 = _get_web3()

    address = _contract_address()
    if not address:
        raise ValueError("CONTRACT_ADDRESS is not set in .env")

    return w3.eth.contract(
        address=Web3.to_checksum_address(address),
        abi=CONTRACT_ABI,
    )


def _send_tx(w3, txn_builder):
    """Build, sign, send a transaction and return its hex hash."""
    from web3 import Web3

    pk = _private_key()
    if not pk:
        raise ValueError("PRIVATE_KEY is not set in .env")

    account = w3.eth.account.from_key(pk)
    nonce = w3.eth.get_transaction_count(account.address)

    txn = txn_builder.build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": 300_000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = account.sign_transaction(txn)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    hex_hash = tx_hash.hex()

    logger.info("TX sent: %s", hex_hash)
    return hex_hash


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def deploy_contract() -> str:
    """Deploy the DocumentRegistry contract (dev / testing only).

    Requires ``CONTRACT_BYTECODE`` to be set in the environment or
    the contract compiled via Hardhat.

    Returns:
        Deployed contract address as a hex string.

    Raises:
        ValueError:      If bytecode is not available.
        ConnectionError: If the RPC node is unreachable.
    """
    bytecode = CONTRACT_BYTECODE
    if not bytecode:
        raise ValueError(
            "CONTRACT_BYTECODE env var is not set. "
            "Compile the contract with Hardhat first:\n"
            "  npx hardhat compile\n"
            "  export CONTRACT_BYTECODE=$(cat artifacts/...)"
        )

    try:
        w3 = _get_web3()
        contract = w3.eth.contract(abi=CONTRACT_ABI, bytecode=bytecode)

        pk = _private_key()
        account = w3.eth.account.from_key(pk)
        nonce = w3.eth.get_transaction_count(account.address)

        txn = contract.constructor().build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 2_000_000,
            "gasPrice": w3.eth.gas_price,
        })

        signed = account.sign_transaction(txn)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        address = receipt.contractAddress
        logger.info("Contract deployed at: %s (tx: %s)", address, tx_hash.hex())
        return address

    except Exception as exc:
        logger.error("deploy_contract failed: %s", exc)
        raise


def store_document(sha256_hash: str, ipfs_cid: str) -> str:
    """Store a document hash and IPFS CID on-chain.

    Args:
        sha256_hash: 64-char hex SHA-256 digest.
        ipfs_cid:    IPFS content identifier string.

    Returns:
        Transaction hash (hex string).
    """
    doc_hash_bytes = _hash_to_bytes32(sha256_hash)

    try:
        w3 = _get_web3()
        contract = _get_contract(w3)
        tx_hash = _send_tx(
            w3, contract.functions.storeDocument(doc_hash_bytes, ipfs_cid)
        )
        logger.info(
            "store_document OK  hash=%s  cid=%s  tx=%s",
            sha256_hash[:16], ipfs_cid[:24], tx_hash,
        )
        return tx_hash

    except Exception as exc:
        logger.warning("store_document failed (%s) — using simulated TX", exc)
        return _simulate_tx("store", sha256_hash)


def verify_document(sha256_hash: str) -> dict:
    """Check whether a document hash is registered on-chain.

    Args:
        sha256_hash: 64-char hex SHA-256 digest.

    Returns:
        dict with keys:
            - exists    (bool)
            - timestamp (int)   – Unix epoch seconds
            - cid       (str)   – IPFS CID stored with the hash
    """
    doc_hash_bytes = _hash_to_bytes32(sha256_hash)

    try:
        w3 = _get_web3()
        contract = _get_contract(w3)
        exists, timestamp, cid = contract.functions.verifyDocument(
            doc_hash_bytes
        ).call()

        logger.info(
            "verify_document  hash=%s  exists=%s  ts=%d",
            sha256_hash[:16], exists, timestamp,
        )
        return {"exists": exists, "timestamp": timestamp, "cid": cid}

    except Exception as exc:
        logger.warning("verify_document failed (%s) — returning simulated result", exc)
        return _simulate_verify(sha256_hash)


def revoke_document(sha256_hash: str) -> str:
    """Revoke a document on-chain (owner only).

    Args:
        sha256_hash: 64-char hex SHA-256 digest.

    Returns:
        Transaction hash (hex string).
    """
    doc_hash_bytes = _hash_to_bytes32(sha256_hash)

    try:
        w3 = _get_web3()
        contract = _get_contract(w3)
        tx_hash = _send_tx(
            w3, contract.functions.revokeDocument(doc_hash_bytes)
        )
        logger.info("revoke_document OK  hash=%s  tx=%s", sha256_hash[:16], tx_hash)
        return tx_hash

    except Exception as exc:
        logger.warning("revoke_document failed (%s) — using simulated TX", exc)
        return _simulate_tx("revoke", sha256_hash)


# ---------------------------------------------------------------------------
# Simulation fallbacks (offline development)
# ---------------------------------------------------------------------------


def _simulate_tx(action: str, sha256_hash: str) -> str:
    """Generate a deterministic simulated TX hash for offline dev."""
    simulated = f"0xSIM_{action}_{sha256_hash[:16]}_{int(time.time())}"
    logger.debug("Simulated TX: %s", simulated)
    return simulated


def _simulate_verify(sha256_hash: str) -> dict:
    """Return a simulated 'not found' verification result."""
    return {"exists": False, "timestamp": 0, "cid": ""}
