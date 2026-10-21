// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {CommonBase} from "forge-std/Base.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IntegratedVerifierBase} from "../../src/baseline/IntegratedVerifierBase.sol";
import {IntegratedRegisterVerifier} from "../../src/baseline/IntegratedRegisterVerifier.sol";
import {IntegratedApplyVerifier} from "../../src/baseline/IntegratedApplyVerifier.sol";
import {IntegratedSettleVerifier} from "../../src/baseline/IntegratedSettleVerifier.sol";
import {TxData} from "../../src/PPREVTypes.sol";

/// @notice Reads the baseline fixtures that offchain/crates/pprev-prover/tests/e1_attestation.rs
/// writes from real notarised sessions: configurations and submissions of the three phases.
abstract contract E1Fixtures is CommonBase {
    using stdJson for string;

    function readFixture(string memory phase) internal view returns (string memory) {
        return vm.readFile(string.concat("test/baseline/fixtures/", phase, ".json"));
    }

    function baseConfig(string memory fx) internal pure returns (IntegratedVerifierBase.BaseConfig memory c) {
        c.notary = fx.readAddress(".attestation.signer");
        c.identityAttestor = fx.readAddress(".identitySigner");
        c.policyId = fx.readBytes32(".statement.policyId");
        c.verifyingKeyHash = keccak256(fx.readBytes(".attestation.fields[0].data"));
        c.serverNameHash = keccak256(bytes(fx.readString(".serverName")));
        c.structureHash = keccak256(fx.readBytes(".structure"));
        bytes[] memory prefixes = fx.readBytesArray(".commitmentPrefixesByRole");
        c.prefixHashes = new bytes32[](prefixes.length);
        for (uint256 r = 0; r < prefixes.length; r++) {
            c.prefixHashes[r] = keccak256(prefixes[r]);
        }
        c.receivedLength = uint32(fx.readUint(".receivedLength"));
        c.delta = 300;
        c.maxSessionSecs = 120;
    }

    function attestation(string memory fx) internal pure returns (IntegratedVerifierBase.Attestation memory a) {
        a.header = fx.readBytes(".attestation.header");
        a.signature = fx.readBytes(".attestation.signature");
        a.verifyingKey = fx.readBytes(".attestation.fields[0].data");
        a.connectionInfo = fx.readBytes(".attestation.fields[1].data");
        a.serverEphemeralKey = fx.readBytes(".attestation.fields[2].data");
        a.certCommitment = fx.readBytes(".attestation.fields[3].data");
        a.tAtt = uint64(fx.readUint(".tAtt"));
        a.prefixes = fx.readBytesArray(".commitmentPrefixesByRole");
        a.hashes = fx.readBytes32Array(".commitmentHashesByRole");
        uint256[] memory roles = fx.readUintArray(".roleOfField");
        a.roleOfField = new uint8[](roles.length);
        for (uint256 i = 0; i < roles.length; i++) {
            a.roleOfField[i] = uint8(roles[i]);
        }
        a.requestBlinder = bytes16(fx.readBytes(".requestBlinder"));
        a.structure = fx.readBytes(".structure");
        a.structureBlinder = bytes16(fx.readBytes(".structureBlinder"));
        a.identitySignature = fx.readBytes(".identitySignature");
    }

    function proof(string memory fx) internal pure returns (IntegratedVerifierBase.Proof memory p) {
        uint256[] memory a = fx.readUintArray(".proof.a");
        uint256[] memory b0 = fx.readUintArray(".proof.b[0]");
        uint256[] memory b1 = fx.readUintArray(".proof.b[1]");
        uint256[] memory c = fx.readUintArray(".proof.c");
        p.a = [a[0], a[1]];
        p.b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        p.c = [c[0], c[1]];
    }

    function txData(string memory fx) internal pure returns (TxData memory) {
        return TxData({
            propertyId: fx.readBytes32(".statement.propertyId"),
            amount: vm.parseUint(fx.readString(".statement.amount")),
            settlementShare: vm.parseUint(fx.readString(".statement.settlementShare"))
        });
    }

    function registerSubmission(string memory fx)
        internal
        pure
        returns (IntegratedRegisterVerifier.Submission memory s)
    {
        s.att = attestation(fx);
        s.cTx = fx.readBytes32(".statement.cTx");
        s.txData = txData(fx);
        s.policyId = fx.readBytes32(".statement.policyId");
        s.submitter = fx.readAddress(".statement.submitter");
        s.eta = fx.readBytes32(".statement.eta");
        s.proof = proof(fx);
    }

    function applySubmission(string memory fx) internal pure returns (IntegratedApplyVerifier.Submission memory s) {
        s.att = attestation(fx);
        s.requestLine = bytes(fx.readString(".requestLine"));
        s.txId = vm.parseUint(fx.readString(".statement.txId"));
        s.cTx = fx.readBytes32(".statement.cTx");
        s.txData = txData(fx);
        s.cB = fx.readBytes32(".statement.cB");
        s.policyId = fx.readBytes32(".statement.policyId");
        s.submitter = fx.readAddress(".statement.submitter");
        s.eta = fx.readBytes32(".statement.eta");
        s.proof = proof(fx);
    }

    function settleSubmission(string memory fx) internal pure returns (IntegratedSettleVerifier.Submission memory s) {
        s.att = attestation(fx);
        s.notationId = bytes(fx.readString(".notationId"));
        s.engId = vm.parseUint(fx.readString(".statement.engId"));
        s.txId = vm.parseUint(fx.readString(".statement.txId"));
        s.cTx = fx.readBytes32(".statement.cTx");
        s.txData = txData(fx);
        s.cB = fx.readBytes32(".statement.cB");
        s.expiresAt = vm.parseUint(fx.readString(".statement.expiresAt"));
        s.policyId = fx.readBytes32(".statement.policyId");
        s.submitter = fx.readAddress(".statement.submitter");
        s.eta = fx.readBytes32(".statement.eta");
        s.proof = proof(fx);
    }
}
