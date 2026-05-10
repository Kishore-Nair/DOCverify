// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract DocumentRegistry is Ownable {
    struct Document {
        bool exists;
        uint256 timestamp;
        string ipfsCid;
        bool revoked;
    }

    mapping(bytes32 => Document) private documents;

    event DocumentStored(bytes32 indexed docHash, string ipfsCid, uint256 timestamp);
    event DocumentRevoked(bytes32 indexed docHash, uint256 timestamp);

    constructor() Ownable(msg.sender) {}

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

    function verifyDocument(bytes32 docHash) public view returns (bool exists, uint256 timestamp, string memory ipfsCid, bool revoked) {
        Document storage doc = documents[docHash];
        return (doc.exists, doc.timestamp, doc.ipfsCid, doc.revoked);
    }

    function revokeDocument(bytes32 docHash) public onlyOwner {
        require(documents[docHash].exists, "Document not found");
        require(!documents[docHash].revoked, "Already revoked");
        documents[docHash].revoked = true;
        emit DocumentRevoked(docHash, block.timestamp);
    }
}
