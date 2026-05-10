// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DocumentRegistry
 * @notice On-chain registry for document hashes and their IPFS CIDs.
 *         Used by Credify to prove document existence at a point in time.
 */
contract DocumentRegistry {
    address public owner;

    struct Document {
        bool exists;
        uint256 timestamp;
        string ipfsCid;
        bool revoked;
    }

    /// docHash (bytes32) => Document metadata
    mapping(bytes32 => Document) private documents;

    // ── Events ──────────────────────────────────────────────────────────

    event DocumentStored(
        bytes32 indexed docHash,
        string ipfsCid,
        uint256 timestamp
    );

    event DocumentRevoked(
        bytes32 indexed docHash,
        uint256 timestamp
    );

    // ── Modifiers ───────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ── Public functions ────────────────────────────────────────────────

    /**
     * @notice Store a document hash with its IPFS CID.
     * @param docHash  SHA-256 digest as bytes32
     * @param ipfsCid  IPFS content identifier string
     */
    function storeDocument(bytes32 docHash, string memory ipfsCid) public {
        require(!documents[docHash].exists, "Document already registered");

        documents[docHash] = Document({
            exists: true,
            timestamp: block.timestamp,
            ipfsCid: ipfsCid,
            revoked: false
        });

        emit DocumentStored(docHash, ipfsCid, block.timestamp);
    }

    /**
     * @notice Verify whether a document hash is registered.
     * @param docHash  SHA-256 digest as bytes32
     * @return exists    Whether the hash is on-chain
     * @return timestamp Block timestamp of registration
     * @return cid       IPFS CID stored with the hash
     */
    function verifyDocument(bytes32 docHash)
        public
        view
        returns (bool exists, uint256 timestamp, string memory cid)
    {
        Document storage doc = documents[docHash];
        return (doc.exists && !doc.revoked, doc.timestamp, doc.ipfsCid);
    }

    /**
     * @notice Revoke a previously stored document (owner only).
     * @param docHash  SHA-256 digest as bytes32
     */
    function revokeDocument(bytes32 docHash) public onlyOwner {
        require(documents[docHash].exists, "Document not found");
        require(!documents[docHash].revoked, "Already revoked");

        documents[docHash].revoked = true;

        emit DocumentRevoked(docHash, block.timestamp);
    }
}
