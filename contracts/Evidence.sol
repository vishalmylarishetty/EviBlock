// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EvidenceManagement {

    struct Evidence {
        string evidenceId;
        string fileHash;
        string fileName;
        string caseId;
        address owner;
        uint256 timestamp;
        bool exists;
    }

    struct CustodyRecord {
        string evidenceId;
        string action;
        address actor;
        string note;
        uint256 timestamp;
    }

    struct MerkleBatch {
        bytes32 root;
        uint256 itemCount;
        address committer;
        uint256 timestamp;
        string caseId;
        bool exists;
    }

    struct Warrant {
        string warrantNumber;
        string caseId;
        address issuedBy;
        uint256 validUntil;
        bool active;
    }

    mapping(string => Evidence) public evidences;
    mapping(string => CustodyRecord[]) public custodyChain;
    mapping(bytes32 => bool) public accessRequests;
    mapping(bytes32 => MerkleBatch) public merkleBatches;
    mapping(string => Warrant) public warrants;

    event EvidenceAdded(string evidenceId, string fileHash, address owner, uint256 timestamp);
    event CustodyTransferred(string evidenceId, string action, address actor, uint256 timestamp);
    event AccessGranted(bytes32 evidenceHash, address requester, string token, uint256 timestamp);
    event MerkleBatchCommitted(bytes32 indexed root, uint256 itemCount, address indexed committer, string caseId, uint256 timestamp);
    event WarrantRegistered(string warrantNumber, string caseId, address indexed issuedBy, uint256 validUntil);
    event WarrantExtended(string warrantNumber, uint256 newValidUntil, address indexed extendedBy);

    // ── Evidence Functions ──────────────────────────────────────────────
    function addEvidence(
        string memory _id,
        string memory _hash,
        string memory _fileName,
        string memory _caseId
    ) public {
        require(!evidences[_id].exists, "Evidence already registered");

        evidences[_id] = Evidence({
            evidenceId: _id,
            fileHash: _hash,
            fileName: _fileName,
            caseId: _caseId,
            owner: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        custodyChain[_id].push(CustodyRecord({
            evidenceId: _id,
            action: "Collected",
            actor: msg.sender,
            note: "Initial evidence registration",
            timestamp: block.timestamp
        }));

        emit EvidenceAdded(_id, _hash, msg.sender, block.timestamp);
    }

    function transferEvidence(
        string memory _id,
        string memory _action,
        string memory _note
    ) public {
        require(evidences[_id].exists, "Evidence not found");

        custodyChain[_id].push(CustodyRecord({
            evidenceId: _id,
            action: _action,
            actor: msg.sender,
            note: _note,
            timestamp: block.timestamp
        }));

        emit CustodyTransferred(_id, _action, msg.sender, block.timestamp);
    }

    function getEvidence(string memory _id)
        public view returns (
            string memory fileHash,
            string memory fileName,
            string memory caseId,
            address owner,
            uint256 timestamp
        )
    {
        require(evidences[_id].exists, "Evidence not found");
        Evidence memory e = evidences[_id];
        return (e.fileHash, e.fileName, e.caseId, e.owner, e.timestamp);
    }

    function getCustodyCount(string memory _id) public view returns (uint256) {
        return custodyChain[_id].length;
    }

    function getCustodyRecord(string memory _id, uint256 index)
        public view returns (
            string memory action,
            address actor,
            string memory note,
            uint256 timestamp
        )
    {
        require(index < custodyChain[_id].length, "Index out of bounds");
        CustodyRecord memory r = custodyChain[_id][index];
        return (r.action, r.actor, r.note, r.timestamp);
    }

    function evidenceExists(string memory _id) public view returns (bool) {
        return evidences[_id].exists;
    }

    function requestAccess(bytes32 evidenceHash, string memory token) public {
        require(bytes(token).length > 0, "Token required");
        accessRequests[evidenceHash] = true;
        emit AccessGranted(evidenceHash, msg.sender, token, block.timestamp);
    }

    // ── Feature 1: Merkle Tree Batching ──────────────────────────────────
    function commitMerkleBatch(
        bytes32 _root,
        uint256 _count,
        string memory _caseId
    ) public {
        require(!merkleBatches[_root].exists, "Merkle batch already committed");
        require(_count > 0, "Item count must be greater than 0");

        merkleBatches[_root] = MerkleBatch({
            root: _root,
            itemCount: _count,
            committer: msg.sender,
            timestamp: block.timestamp,
            caseId: _caseId,
            exists: true
        });

        emit MerkleBatchCommitted(_root, _count, msg.sender, _caseId, block.timestamp);
    }

    function verifyMerkleProof(
        bytes32 _leaf,
        bytes32[] memory _proof,
        bytes32 _root
    ) public pure returns (bool) {
        bytes32 computedHash = _leaf;

        for (uint256 i = 0; i < _proof.length; i++) {
            bytes32 proofElement = _proof[i];

            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == _root;
    }

    function getMerkleBatch(bytes32 _root)
        public view returns (
            uint256 itemCount,
            address committer,
            uint256 timestamp,
            string memory caseId
        )
    {
        require(merkleBatches[_root].exists, "Merkle batch not found");
        MerkleBatch memory b = merkleBatches[_root];
        return (b.itemCount, b.committer, b.timestamp, b.caseId);
    }

    // ── Feature 2: Expiring Smart Warrants ──────────────────────────────
    function registerWarrant(
        string memory _warrantNumber,
        string memory _caseId,
        uint256 _durationSeconds
    ) public {
        require(_durationSeconds > 0, "Duration must be greater than 0");
        uint256 validUntil = block.timestamp + _durationSeconds;

        warrants[_warrantNumber] = Warrant({
            warrantNumber: _warrantNumber,
            caseId: _caseId,
            issuedBy: msg.sender,
            validUntil: validUntil,
            active: true
        });

        emit WarrantRegistered(_warrantNumber, _caseId, msg.sender, validUntil);
    }

    function isWarrantValid(string memory _warrantNumber) public view returns (bool) {
        if (!warrants[_warrantNumber].active) {
            return false;
        }
        return block.timestamp <= warrants[_warrantNumber].validUntil;
    }

    function extendWarrant(
        string memory _warrantNumber,
        uint256 _additionalSeconds
    ) public {
        require(warrants[_warrantNumber].active, "Warrant does not exist or inactive");
        require(_additionalSeconds > 0, "Additional time must be greater than 0");

        warrants[_warrantNumber].validUntil += _additionalSeconds;
        emit WarrantExtended(_warrantNumber, warrants[_warrantNumber].validUntil, msg.sender);
    }

    function getWarrant(string memory _warrantNumber)
        public view returns (
            string memory caseId,
            address issuedBy,
            uint256 validUntil,
            bool active,
            bool isValid
        )
    {
        require(warrants[_warrantNumber].active, "Warrant not found");
        Warrant memory w = warrants[_warrantNumber];
        bool valid = block.timestamp <= w.validUntil;
        return (w.caseId, w.issuedBy, w.validUntil, w.active, valid);
    }
}
