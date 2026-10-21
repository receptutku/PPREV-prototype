// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PPREVEncoding} from "../PPREVEncoding.sol";
import {TxData} from "../PPREVTypes.sol";
import {IntegratedVerifierBase} from "./IntegratedVerifierBase.sol";

/// @notice The exported Groth16 verifier of phi_S (snarkjs), eleven public inputs.
interface IPhiSVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[11] calldata pubSignals
    ) external view returns (bool);
}

/// @title Integrated on-chain verification of a Settle submission (measurement baseline)
/// @notice The tenancy layout (roles: structure, request line, account, propertyId, tenant,
/// recordDate) and phi_S, with its public inputs from the attested commitments and x_S; the
/// engagement day is computed on-chain from expiresAt, the deployment's tau_lock, and the
/// registry's time zone. See IntegratedVerifierBase.
contract IntegratedSettleVerifier is IntegratedVerifierBase {
    uint256 internal constant ROLE_PROPERTY = 3;
    uint256 internal constant ROLE_TENANT = 4;
    uint256 internal constant ROLE_DATE = 5;

    IPhiSVerifier public immutable PHI_S;
    uint64 public immutable TAU_LOCK;
    int64 public immutable UTC_OFFSET_SECS;

    error BadPublicInput();
    error BadNotation();

    struct Submission {
        Attestation att;
        bytes notationId;
        uint256 engId;
        uint256 txId;
        bytes32 cTx;
        TxData txData;
        bytes32 cB;
        uint256 expiresAt;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        Proof proof;
    }

    constructor(BaseConfig memory c, IPhiSVerifier phiS, uint64 tauLock, int64 utcOffsetSecs)
        IntegratedVerifierBase(c)
    {
        if (c.prefixHashes.length != 6) revert BadConfig();
        PHI_S = phiS;
        TAU_LOCK = tauLock;
        UTC_OFFSET_SECS = utcOffsetSecs;
    }

    /// @notice Accepts a Settle submission or reverts with the first failed check.
    function verify(Submission calldata s) external view returns (bool) {
        _checkNotation(s.notationId);
        // GET /tenancy/{notationId} HTTP/1.1
        _checkAttestation(s.att, abi.encodePacked("GET /tenancy/", s.notationId, " HTTP/1.1"), s.policyId);
        if (uint256(s.cB) >= R) revert BadPublicInput();
        uint256[11] memory pub;
        (pub[0], pub[1]) = _limbs(s.att.hashes[ROLE_PROPERTY]);
        (pub[2], pub[3]) = _limbs(s.att.hashes[ROLE_TENANT]);
        (pub[4], pub[5]) = _limbs(s.att.hashes[ROLE_DATE]);
        (pub[6], pub[7]) = _limbs(s.txData.propertyId);
        pub[8] = uint256(s.cB);
        pub[9] = engagementDay(s.expiresAt);
        pub[10] = uint256(_typedDataHash(_settleStructHash(s))) % R;
        if (!PHI_S.verifyProof(s.proof.a, s.proof.b, s.proof.c, pub)) revert BadProof();
        return true;
    }

    function _settleStructHash(Submission calldata s) internal pure returns (bytes32) {
        PPREVEncoding.SettleStatement memory x;
        x.engId = s.engId;
        x.txId = s.txId;
        x.cTx = s.cTx;
        x.txDataHash = PPREVEncoding.hashTxData(s.txData);
        x.cB = s.cB;
        x.expiresAt = s.expiresAt;
        x.policyId = s.policyId;
        x.submitter = s.submitter;
        x.eta = s.eta;
        x.tAtt = s.att.tAtt;
        return PPREVEncoding.hashSettle(x);
    }

    /// A request target segment: letters, digits, and '-' only, 1 to 64 bytes.
    function _checkNotation(bytes calldata id) internal pure {
        if (id.length == 0 || id.length > 64) revert BadNotation();
        for (uint256 i = 0; i < id.length; i++) {
            bytes1 b = id[i];
            bool ok = (b >= "0" && b <= "9") || (b >= "A" && b <= "Z") || (b >= "a" && b <= "z") || b == "-";
            if (!ok) revert BadNotation();
        }
    }

    /// Y * 10000 + M * 100 + D of the calendar day, in the registry's time zone, of
    /// expiresAt - tau_lock (pprev-types calendar::engagement_day; H. Hinnant's civil_from_days).
    function engagementDay(uint256 expiresAt) public view returns (uint256) {
        if (expiresAt < TAU_LOCK || expiresAt > type(uint64).max) revert BadPublicInput();
        int256 local = int256(expiresAt - TAU_LOCK) + UTC_OFFSET_SECS;
        int256 days_ = local >= 0 ? local / 86400 : (local - 86399) / 86400;
        int256 z = days_ + 719468;
        int256 era = (z >= 0 ? z : z - 146096) / 146097;
        int256 doe = z - era * 146097;
        int256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        int256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        int256 mp = (5 * doy + 2) / 153;
        int256 d = doy - (153 * mp + 2) / 5 + 1;
        int256 m = mp < 10 ? mp + 3 : mp - 9;
        int256 y = yoe + era * 400 + (m <= 2 ? int256(1) : int256(0));
        if (y < 0 || y > 9999) revert BadPublicInput();
        return uint256(y * 10000 + m * 100 + d);
    }
}
