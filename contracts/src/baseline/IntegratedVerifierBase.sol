// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Common part of the integrated on-chain verification baseline
/// @notice Checks on-chain what PPREV's policy verifier checks off-chain about a TLSNotary
/// attestation, for one response layout: the attestation signature, every body field against the
/// signed Merkle root (exact schema: four fixed fields, one t_att extension, and one transcript
/// commitment per role, each role exactly once), the attestation time against the handshake time
/// and the freshness window, the received length, and the revealed request line and response
/// structure. The server identity (certificate chain, DNS name) is not checked here: an off-chain
/// identity attestor signs it for the signed header, and this contract checks that signature. The
/// notary remains trusted for the authenticity of the TLS session. A measurement baseline, not part
/// of PPREV's deployment; PPREV.sol is unchanged.
/// @dev Encoding of tlsn v0.1.0-alpha.15 with the SECP256K1ETH signature and KECCAK256 tree, as
/// offchain/crates/pprev-prover/src/e1.rs documents and tests against tlsn itself.
abstract contract IntegratedVerifierBase {
    /// First 16 bytes of BLAKE3 of each field type's name (tlsn impl_domain_separator!).
    bytes16 internal constant DOMAIN_VERIFYING_KEY = 0xaec37d45b99c4e4b637706b1e978a3eb;
    bytes16 internal constant DOMAIN_CONNECTION_INFO = 0x6e317487904af460f6bba793610c9961;
    bytes16 internal constant DOMAIN_SERVER_EPHEMERAL_KEY = 0x23302af3213e5b0a44d3f7ba9cf33e93;
    bytes16 internal constant DOMAIN_CERT_COMMITMENT = 0xd0f7107feb7eec1e5793d2e8a2b696f0;
    bytes16 internal constant DOMAIN_EXTENSION = 0x67ed567f312ca482b9f365cc271baa42;
    bytes16 internal constant DOMAIN_TRANSCRIPT_COMMITMENT = 0xbd0ab9ac6ea93ebda2500e8769e63a9e;

    /// Header: id (16), version u32 LE (4), root: alg (1), length (1), digest (32).
    uint256 internal constant HEADER_LENGTH = 54;
    uint8 internal constant HASH_ALG_KECCAK256 = 3;
    /// ConnectionInfo: time u64 LE (8), TLS version (1; 0 = TLS 1.2), sent u32 LE, received u32 LE.
    uint256 internal constant CONNECTION_INFO_LENGTH = 17;
    /// Fields before the transcript commitments: four fixed fields and the t_att extension.
    uint256 internal constant FIXED_FIELDS = 5;
    uint256 internal constant MAX_COMMITMENTS = 6;
    /// The first two roles of every layout; the hidden fields follow.
    uint256 internal constant ROLE_STRUCTURE = 0;
    uint256 internal constant ROLE_REQUEST = 1;

    /// tlsn's MPC-TLS follower accepts a handshake time at most this far ahead of its clock.
    uint256 internal constant TLSN_CLOCK_TOLERANCE = 5;
    /// BN254 scalar field order.
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant IDENTITY_TAG = keccak256("PPREV.identity.v1");

    struct BaseConfig {
        address notary;
        address identityAttestor;
        bytes32 policyId;
        bytes32 verifyingKeyHash;
        bytes32 serverNameHash;
        bytes32 structureHash;
        /// keccak256 of each role's commitment prefix (direction and ranges), in role order.
        bytes32[] prefixHashes;
        uint32 receivedLength;
        uint64 delta;
        uint64 maxSessionSecs;
    }

    address public immutable NOTARY;
    address public immutable IDENTITY_ATTESTOR;
    bytes32 public immutable POLICY_ID;
    bytes32 public immutable VERIFYING_KEY_HASH;
    bytes32 public immutable SERVER_NAME_HASH;
    bytes32 public immutable STRUCTURE_HASH;
    uint256 public immutable COMMITMENTS;
    bytes32 internal immutable PREFIX_HASH_0;
    bytes32 internal immutable PREFIX_HASH_1;
    bytes32 internal immutable PREFIX_HASH_2;
    bytes32 internal immutable PREFIX_HASH_3;
    bytes32 internal immutable PREFIX_HASH_4;
    bytes32 internal immutable PREFIX_HASH_5;
    uint32 public immutable RECEIVED_LENGTH;
    uint64 public immutable DELTA;
    uint64 public immutable MAX_SESSION_SECS;

    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// An attestation and the openings of its revealed commitments.
    struct Attestation {
        bytes header;
        bytes signature;
        bytes verifyingKey;
        bytes connectionInfo;
        bytes serverEphemeralKey;
        bytes certCommitment;
        uint64 tAtt;
        /// Per role: the commitment's prefix and hash.
        bytes[] prefixes;
        bytes32[] hashes;
        /// Role of each transcript-commitment field, in field-id order.
        uint8[] roleOfField;
        bytes16 requestBlinder;
        bytes structure;
        bytes16 structureBlinder;
        bytes identitySignature;
    }

    error BadConfig();
    error BadHeader();
    error BadSignature();
    error BadIdentity();
    error UnknownPolicy();
    error BadVerifyingKey();
    error BadConnectionInfo();
    error BadTime();
    error NotFresh();
    error BadRoles();
    error BadPrefix(uint256 role);
    error BadRequestLine();
    error BadStructure();
    error BadRoot();
    error BadProof();

    constructor(BaseConfig memory c) {
        uint256 n = c.prefixHashes.length;
        if (n < 3 || n > MAX_COMMITMENTS) revert BadConfig();
        NOTARY = c.notary;
        IDENTITY_ATTESTOR = c.identityAttestor;
        POLICY_ID = c.policyId;
        VERIFYING_KEY_HASH = c.verifyingKeyHash;
        SERVER_NAME_HASH = c.serverNameHash;
        STRUCTURE_HASH = c.structureHash;
        COMMITMENTS = n;
        PREFIX_HASH_0 = c.prefixHashes[0];
        PREFIX_HASH_1 = c.prefixHashes[1];
        PREFIX_HASH_2 = c.prefixHashes[2];
        PREFIX_HASH_3 = n > 3 ? c.prefixHashes[3] : bytes32(0);
        PREFIX_HASH_4 = n > 4 ? c.prefixHashes[4] : bytes32(0);
        PREFIX_HASH_5 = n > 5 ? c.prefixHashes[5] : bytes32(0);
        RECEIVED_LENGTH = c.receivedLength;
        DELTA = c.delta;
        MAX_SESSION_SECS = c.maxSessionSecs;
    }

    /// Checks the attestation for `policyId` with the revealed request line `requestLine`.
    function _checkAttestation(Attestation calldata a, bytes memory requestLine, bytes32 policyId) internal view {
        if (policyId != POLICY_ID) revert UnknownPolicy();
        bytes32 root = _header(a.header);
        bytes32 headerHash = keccak256(a.header);
        if (_recover(headerHash, a.signature) != NOTARY) revert BadSignature();
        bytes32 identityDigest = keccak256(abi.encode(IDENTITY_TAG, headerHash, NOTARY, SERVER_NAME_HASH, policyId));
        if (_recover(identityDigest, a.identitySignature) != IDENTITY_ATTESTOR) revert BadIdentity();
        if (keccak256(a.verifyingKey) != VERIFYING_KEY_HASH) revert BadVerifyingKey();
        _connection(a.connectionInfo, a.tAtt);

        // Commitments: each role exactly once, each with its layout prefix.
        uint256 n = COMMITMENTS;
        if (a.prefixes.length != n || a.hashes.length != n || a.roleOfField.length != n) revert BadRoles();
        uint256 seen;
        for (uint256 i = 0; i < n; i++) {
            if (a.roleOfField[i] >= n) revert BadRoles();
            seen |= 1 << a.roleOfField[i];
        }
        if (seen != (1 << n) - 1) revert BadRoles();
        for (uint256 r = 0; r < n; r++) {
            if (keccak256(a.prefixes[r]) != _prefixHash(r)) revert BadPrefix(r);
        }
        if (sha256(abi.encodePacked(requestLine, a.requestBlinder)) != a.hashes[ROLE_REQUEST]) {
            revert BadRequestLine();
        }
        if (
            keccak256(a.structure) != STRUCTURE_HASH
                || sha256(abi.encodePacked(a.structure, a.structureBlinder)) != a.hashes[ROLE_STRUCTURE]
        ) revert BadStructure();

        // Leaves in field-id order, and the root.
        bytes32[] memory leaves = new bytes32[](FIXED_FIELDS + n);
        leaves[0] = keccak256(abi.encodePacked(DOMAIN_VERIFYING_KEY, a.verifyingKey));
        leaves[1] = keccak256(abi.encodePacked(DOMAIN_CONNECTION_INFO, a.connectionInfo));
        leaves[2] = keccak256(abi.encodePacked(DOMAIN_SERVER_EPHEMERAL_KEY, a.serverEphemeralKey));
        leaves[3] = keccak256(abi.encodePacked(DOMAIN_CERT_COMMITMENT, a.certCommitment));
        // Extension { id: "pprev.t_att", value: t_att as u64 big-endian }.
        leaves[4] = keccak256(abi.encodePacked(DOMAIN_EXTENSION, hex"0b", "pprev.t_att", hex"08", bytes8(a.tAtt)));
        for (uint256 i = 0; i < n; i++) {
            uint256 r = a.roleOfField[i];
            // TranscriptCommitment::Hash { .., hash: TypedHash { alg: SHA256 (1), 32 bytes } }.
            leaves[FIXED_FIELDS + i] =
                keccak256(abi.encodePacked(DOMAIN_TRANSCRIPT_COMMITMENT, a.prefixes[r], hex"0120", a.hashes[r]));
        }
        if (_merkleRoot(leaves) != root) revert BadRoot();
    }

    function _header(bytes calldata h) internal pure returns (bytes32 root) {
        if (h.length != HEADER_LENGTH) revert BadHeader();
        // Version 0, Keccak-256 root of 32 bytes.
        if (bytes4(h[16:20]) != bytes4(0) || uint8(h[20]) != HASH_ALG_KECCAK256 || uint8(h[21]) != 32) {
            revert BadHeader();
        }
        root = bytes32(h[22:54]);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        // Reject malleable signatures (s in the upper half of the order).
        if (uint256(bytes32(sig[32:64])) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSignature();
        }
        address a = ecrecover(digest, v, bytes32(sig[0:32]), bytes32(sig[32:64]));
        if (a == address(0)) revert BadSignature();
        return a;
    }

    function _connection(bytes calldata c, uint64 tAtt) internal view {
        if (c.length != CONNECTION_INFO_LENGTH || uint8(c[8]) != 0) revert BadConnectionInfo();
        uint64 time = uint64(_le(c[0:8]));
        if (uint32(_le(c[13:17])) != RECEIVED_LENGTH) revert BadConnectionInfo();
        if (uint256(tAtt) + TLSN_CLOCK_TOLERANCE < time || tAtt > time + MAX_SESSION_SECS) revert BadTime();
        // forge-lint: disable-next-line(block-timestamp)
        if (tAtt > block.timestamp || block.timestamp - tAtt > DELTA) revert NotFresh();
    }

    /// Little-endian unsigned integer of up to 32 bytes.
    function _le(bytes calldata b) internal pure returns (uint256 v) {
        for (uint256 i = b.length; i > 0; i--) {
            v = (v << 8) | uint8(b[i - 1]);
        }
    }

    function _prefixHash(uint256 r) internal view returns (bytes32) {
        if (r == 0) return PREFIX_HASH_0;
        if (r == 1) return PREFIX_HASH_1;
        if (r == 2) return PREFIX_HASH_2;
        if (r == 3) return PREFIX_HASH_3;
        if (r == 4) return PREFIX_HASH_4;
        return PREFIX_HASH_5;
    }

    /// tlsn's Merkle root: inner node keccak256(left || right); a node without a sibling moves up.
    function _merkleRoot(bytes32[] memory layer) internal pure returns (bytes32) {
        uint256 n = layer.length;
        while (n > 1) {
            uint256 m = (n + 1) / 2;
            for (uint256 i = 0; i < m; i++) {
                layer[i] = 2 * i + 1 < n ? keccak256(abi.encodePacked(layer[2 * i], layer[2 * i + 1])) : layer[2 * i];
            }
            n = m;
        }
        return layer[0];
    }

    function _limbs(bytes32 w) internal pure returns (uint256 hi, uint256 lo) {
        hi = uint256(w) >> 128;
        lo = uint256(w) & type(uint128).max;
    }

    /// EIP-712 digest of `structHash` in this contract's domain (PPREV's domain fields).
    function _typedDataHash(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domainSeparator =
            keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("PPREV"), keccak256("1"), block.chainid, address(this)));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// The property identifier without its padding: the word up to its first zero byte, then
    /// without trailing spaces.
    function _unpadded(bytes32 word) internal pure returns (bytes memory id) {
        uint256 n = 0;
        while (n < 32 && word[n] != 0) n++;
        while (n > 0 && word[n - 1] == 0x20) n--;
        id = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            id[i] = word[i];
        }
    }
}
