// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PPREVEncoding} from "../PPREVEncoding.sol";
import {TxData} from "../PPREVTypes.sol";
import {IntegratedVerifierBase} from "./IntegratedVerifierBase.sol";

/// @notice The exported Groth16 verifier of phi_R (snarkjs), nine public inputs.
interface IPhiRVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[9] calldata pubSignals
    ) external view returns (bool);
}

/// @title Integrated on-chain verification of a Register submission (measurement baseline)
/// @notice The title layout (roles: structure, request line, account, owners, propertyId) and phi_R,
/// with its public inputs from the attested commitments and x_R. See IntegratedVerifierBase.
contract IntegratedRegisterVerifier is IntegratedVerifierBase {
    uint256 internal constant ROLE_ACCOUNT = 2;
    uint256 internal constant ROLE_OWNERS = 3;
    uint256 internal constant ROLE_PROPERTY = 4;

    IPhiRVerifier public immutable PHI_R;

    struct Submission {
        Attestation att;
        bytes32 cTx;
        TxData txData;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        Proof proof;
    }

    constructor(BaseConfig memory c, IPhiRVerifier phiR) IntegratedVerifierBase(c) {
        if (c.prefixHashes.length != 5) revert BadConfig();
        PHI_R = phiR;
    }

    /// @notice Accepts a Register submission or reverts with the first failed check.
    function verify(Submission calldata s) external view returns (bool) {
        // GET /title/{propertyId} HTTP/1.1
        _checkAttestation(
            s.att, abi.encodePacked("GET /title/", _unpadded(s.txData.propertyId), " HTTP/1.1"), s.policyId
        );
        PPREVEncoding.RegisterStatement memory x;
        x.cTx = s.cTx;
        x.txDataHash = PPREVEncoding.hashTxData(s.txData);
        x.policyId = s.policyId;
        x.submitter = s.submitter;
        x.eta = s.eta;
        x.tAtt = s.att.tAtt;
        uint256[9] memory pub;
        (pub[0], pub[1]) = _limbs(s.att.hashes[ROLE_ACCOUNT]);
        (pub[2], pub[3]) = _limbs(s.att.hashes[ROLE_OWNERS]);
        (pub[4], pub[5]) = _limbs(s.att.hashes[ROLE_PROPERTY]);
        (pub[6], pub[7]) = _limbs(s.txData.propertyId);
        pub[8] = uint256(_typedDataHash(PPREVEncoding.hashRegister(x))) % R;
        if (!PHI_R.verifyProof(s.proof.a, s.proof.b, s.proof.c, pub)) revert BadProof();
        return true;
    }
}
