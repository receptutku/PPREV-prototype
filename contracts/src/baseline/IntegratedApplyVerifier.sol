// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PPREVEncoding} from "../PPREVEncoding.sol";
import {TxData} from "../PPREVTypes.sol";
import {IntegratedVerifierBase} from "./IntegratedVerifierBase.sol";

/// @notice The exported Groth16 verifier of phi_A (snarkjs), seven public inputs.
interface IPhiAVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[7] calldata pubSignals
    ) external view returns (bool);
}

/// @title Integrated on-chain verification of an Apply submission (measurement baseline)
/// @notice The income layout (roles: structure, request line, account, monthlyIncome) and phi_A,
/// with its public inputs from the attested commitments and x_A. The request line is fixed by the
/// layout. See IntegratedVerifierBase.
contract IntegratedApplyVerifier is IntegratedVerifierBase {
    uint256 internal constant ROLE_ACCOUNT = 2;
    uint256 internal constant ROLE_INCOME = 3;
    /// phi_A bounds txData.amount (PHI_A_AMOUNT_BITS in pprev-types).
    uint256 internal constant AMOUNT_BITS = 96;

    IPhiAVerifier public immutable PHI_A;
    bytes32 public immutable REQUEST_LINE_HASH;

    error BadPublicInput();

    struct Submission {
        Attestation att;
        bytes requestLine;
        uint256 txId;
        bytes32 cTx;
        TxData txData;
        bytes32 cB;
        bytes32 policyId;
        address submitter;
        bytes32 eta;
        Proof proof;
    }

    constructor(BaseConfig memory c, IPhiAVerifier phiA, bytes32 requestLineHash) IntegratedVerifierBase(c) {
        if (c.prefixHashes.length != 4) revert BadConfig();
        PHI_A = phiA;
        REQUEST_LINE_HASH = requestLineHash;
    }

    /// @notice Accepts an Apply submission or reverts with the first failed check.
    function verify(Submission calldata s) external view returns (bool) {
        if (keccak256(s.requestLine) != REQUEST_LINE_HASH) revert BadRequestLine();
        _checkAttestation(s.att, s.requestLine, s.policyId);
        if (uint256(s.cB) >= R || s.txData.amount >> AMOUNT_BITS != 0) revert BadPublicInput();
        PPREVEncoding.ApplyStatement memory x;
        x.txId = s.txId;
        x.cTx = s.cTx;
        x.txDataHash = PPREVEncoding.hashTxData(s.txData);
        x.cB = s.cB;
        x.policyId = s.policyId;
        x.submitter = s.submitter;
        x.eta = s.eta;
        x.tAtt = s.att.tAtt;
        uint256[7] memory pub;
        (pub[0], pub[1]) = _limbs(s.att.hashes[ROLE_ACCOUNT]);
        (pub[2], pub[3]) = _limbs(s.att.hashes[ROLE_INCOME]);
        pub[4] = uint256(s.cB);
        pub[5] = s.txData.amount;
        pub[6] = uint256(_typedDataHash(PPREVEncoding.hashApply(x))) % R;
        if (!PHI_A.verifyProof(s.proof.a, s.proof.b, s.proof.c, pub)) revert BadProof();
        return true;
    }
}
