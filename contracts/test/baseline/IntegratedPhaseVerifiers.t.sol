// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Groth16Verifier as PhiAGroth16} from "pprev-circuits/phi_a/Groth16Verifier.sol";
import {Groth16Verifier as PhiSGroth16} from "pprev-circuits/phi_s/Groth16Verifier.sol";
import {IntegratedVerifierBase} from "../../src/baseline/IntegratedVerifierBase.sol";
import {IntegratedApplyVerifier, IPhiAVerifier} from "../../src/baseline/IntegratedApplyVerifier.sol";
import {IntegratedSettleVerifier, IPhiSVerifier} from "../../src/baseline/IntegratedSettleVerifier.sol";
import {E1Fixtures} from "./E1Fixtures.sol";

/// @notice The Apply and Settle baselines on real attestations (income and tenancy sessions), and the
/// rejection of their phase-specific parts; the common attestation checks are exercised by the
/// Register suite.
contract IntegratedApplyVerifierTest is Test, E1Fixtures {
    using stdJson for string;

    string internal fx;
    IntegratedApplyVerifier internal baseline;

    function setUp() public {
        fx = readFixture("apply");
        PhiAGroth16 phiA = new PhiAGroth16();
        deployCodeTo(
            "IntegratedApplyVerifier.sol:IntegratedApplyVerifier",
            abi.encode(baseConfig(fx), IPhiAVerifier(address(phiA)), keccak256(bytes(fx.readString(".requestLine")))),
            fx.readAddress(".baseline")
        );
        baseline = IntegratedApplyVerifier(fx.readAddress(".baseline"));
        vm.chainId(fx.readUint(".chainId"));
        vm.warp(fx.readUint(".tAtt") + 10);
    }

    function test_accepts_the_real_submission() public view {
        assertTrue(baseline.verify(applySubmission(fx)));
    }

    function test_rejects_another_request_line() public {
        IntegratedApplyVerifier.Submission memory s = applySubmission(fx);
        s.requestLine = bytes("GET /title/x HTTP/1.1");
        vm.expectRevert(IntegratedVerifierBase.BadRequestLine.selector);
        baseline.verify(s);
    }

    function test_rejects_a_c_b_aliasing_above_the_field() public {
        IntegratedApplyVerifier.Submission memory s = applySubmission(fx);
        s.cB = bytes32(uint256(s.cB) + 21888242871839275222246405745257275088548364400416034343698204186575808495617);
        vm.expectRevert(IntegratedApplyVerifier.BadPublicInput.selector);
        baseline.verify(s);
    }

    function test_rejects_an_amount_of_96_bits() public {
        IntegratedApplyVerifier.Submission memory s = applySubmission(fx);
        s.txData.amount = 1 << 96;
        vm.expectRevert(IntegratedApplyVerifier.BadPublicInput.selector);
        baseline.verify(s);
    }

    function test_rejects_another_c_b() public {
        IntegratedApplyVerifier.Submission memory s = applySubmission(fx);
        s.cB = bytes32(uint256(s.cB) ^ 1);
        vm.expectRevert(IntegratedVerifierBase.BadProof.selector);
        baseline.verify(s);
    }

    function test_rejects_another_listing() public {
        IntegratedApplyVerifier.Submission memory s = applySubmission(fx);
        s.txId = 2;
        vm.expectRevert(IntegratedVerifierBase.BadProof.selector);
        baseline.verify(s);
    }
}

contract IntegratedSettleVerifierTest is Test, E1Fixtures {
    using stdJson for string;

    string internal fx;
    IntegratedSettleVerifier internal baseline;

    function setUp() public {
        fx = readFixture("settle");
        PhiSGroth16 phiS = new PhiSGroth16();
        deployCodeTo(
            "IntegratedSettleVerifier.sol:IntegratedSettleVerifier",
            abi.encode(
                baseConfig(fx),
                IPhiSVerifier(address(phiS)),
                uint64(fx.readUint(".tauLock")),
                int64(fx.readInt(".utcOffsetSecs"))
            ),
            fx.readAddress(".baseline")
        );
        baseline = IntegratedSettleVerifier(fx.readAddress(".baseline"));
        vm.chainId(fx.readUint(".chainId"));
        vm.warp(fx.readUint(".tAtt") + 10);
    }

    function test_accepts_the_real_submission() public view {
        assertTrue(baseline.verify(settleSubmission(fx)));
    }

    function test_the_engagement_day_matches_the_off_chain_derivation() public view {
        assertEq(
            baseline.engagementDay(vm.parseUint(fx.readString(".statement.expiresAt"))), fx.readUint(".engagementDay")
        );
        // 2024-02-29 and the day after, in UTC+3.
        uint256 tau = fx.readUint(".tauLock");
        assertEq(baseline.engagementDay(1709154000 + tau), 20240229);
        assertEq(baseline.engagementDay(1709240399 + tau), 20240229);
        assertEq(baseline.engagementDay(1709240400 + tau), 20240301);
    }

    function test_rejects_another_notation() public {
        IntegratedSettleVerifier.Submission memory s = settleSubmission(fx);
        s.notationId = bytes("N-0002");
        vm.expectRevert(IntegratedVerifierBase.BadRequestLine.selector);
        baseline.verify(s);
    }

    function test_rejects_a_notation_that_changes_the_request_line() public {
        IntegratedSettleVerifier.Submission memory s = settleSubmission(fx);
        s.notationId = bytes("N-0001 HTTP/1.1");
        vm.expectRevert(IntegratedSettleVerifier.BadNotation.selector);
        baseline.verify(s);
    }

    function test_rejects_another_expiry() public {
        // Another engagement day, and another statement.
        IntegratedSettleVerifier.Submission memory s = settleSubmission(fx);
        s.expiresAt -= 86400;
        vm.expectRevert(IntegratedVerifierBase.BadProof.selector);
        baseline.verify(s);
    }

    function test_rejects_another_property() public {
        IntegratedSettleVerifier.Submission memory s = settleSubmission(fx);
        s.txData.propertyId = bytes32(uint256(s.txData.propertyId) ^ (1 << 200));
        vm.expectRevert(IntegratedVerifierBase.BadProof.selector);
        baseline.verify(s);
    }

    function test_rejects_a_c_b_aliasing_above_the_field() public {
        IntegratedSettleVerifier.Submission memory s = settleSubmission(fx);
        s.cB = bytes32(uint256(s.cB) + 21888242871839275222246405745257275088548364400416034343698204186575808495617);
        vm.expectRevert(IntegratedSettleVerifier.BadPublicInput.selector);
        baseline.verify(s);
    }
}
