// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow, RegisterCall, ApplyCall} from "./utils/Fixture.sol";
import {PPREV} from "../src/PPREV.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {EcdsaNotaryVerifier} from "../src/verifiers/EcdsaNotaryVerifier.sol";
import {
    Policy,
    PolicyRegistered,
    NotaryVerifierSet,
    NotaryVerifierProposed,
    NotaryVerifierProposalCancelled,
    NotOperator,
    InvalidParameters,
    PolicyExists,
    NoPendingVerifier,
    RotationNotDue,
    InvalidNotarySignature
} from "../src/PPREVTypes.sol";

/// @notice Setup parameters and the administrative operations of Section V-C.
contract AdminTest is Fixture {
    bytes32 internal constant P_R = keccak256("admin.register");
    bytes32 internal constant P_A = keccak256("admin.apply");
    bytes32 internal constant P_S = keccak256("admin.settle");

    function policyOf(bytes32 policyIdR) internal view returns (Policy memory p) {
        (p.exists, p.policyIdA, p.policyIdS, p.reqEscrow, p.minCollateral, p.maxCollateral) =
            pprev.policyRegistry(policyIdR);
    }

    // ------------------------------------------------------------------ constructor

    function test_Constructor_fixesPublicParameters() public view {
        assertEq(pprev.OPERATOR(), operator);
        assertEq(pprev.DELTA(), DELTA);
        assertEq(pprev.TAU_LOCK(), TAU_LOCK);
        assertEq(pprev.MAX_EXPIRATIONS(), MAX_EXPIRATIONS);
        assertEq(pprev.RHO(), RHO);
        assertEq(pprev.ROTATION_DELAY(), ROTATION_DELAY);
        assertEq(address(pprev.notaryVerifier()), address(verifier));
        assertEq(pprev.notaryKeyVersion(), 1);
        assertEq(address(pprev.notaryVerifierAt(1)), address(verifier));
        assertEq(address(pprev.notaryVerifierAt(2)), address(0));
        assertEq(address(pprev.pendingNotaryVerifier()), address(0));
        assertEq(pprev.pendingEffectiveAt(), 0);
        assertEq(pprev.nextTxId(), 1);
        assertEq(pprev.nextAppId(), 1);
        assertEq(pprev.nextEngId(), 1);
        assertEq(pprev.domainSeparator(), domainSeparatorFor(vm.getChainId(), address(pprev)));
    }

    function test_Constructor_emitsVerifierAsVersionOne() public {
        vm.expectEmit();
        emit NotaryVerifierSet(address(verifier), 1);
        new PPREV(operator, INotaryVerifier(address(verifier)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, ROTATION_DELAY);
    }

    function test_Constructor_revertsForInvalidParameters() public {
        INotaryVerifier v = INotaryVerifier(address(verifier));
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(address(0), v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, ROTATION_DELAY);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, INotaryVerifier(address(0)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, ROTATION_DELAY);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, 0, TAU_LOCK, MAX_EXPIRATIONS, RHO, ROTATION_DELAY);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, 0, MAX_EXPIRATIONS, RHO, ROTATION_DELAY);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, TAU_LOCK, 0, RHO, ROTATION_DELAY);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, 0, ROTATION_DELAY);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, 10_000, ROTATION_DELAY);
    }

    function test_Constructor_revertsForZeroRotationDelay() public {
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, INotaryVerifier(address(verifier)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, 0);
    }

    function test_Constructor_revertsForRotationDelayBelowLockWindow() public {
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, INotaryVerifier(address(verifier)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, TAU_LOCK - 1);
    }

    function test_Constructor_acceptsRotationDelayOfAtLeastLockWindow() public {
        INotaryVerifier v = INotaryVerifier(address(verifier));
        assertEq(new PPREV(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, TAU_LOCK).ROTATION_DELAY(), TAU_LOCK);
        assertEq(
            new PPREV(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, TAU_LOCK + 1).ROTATION_DELAY(), TAU_LOCK + 1
        );
    }

    // ------------------------------------------------------------------ registerPolicy

    function test_RegisterPolicy_storesBundleAndEmits() public {
        vm.expectEmit(address(pprev));
        emit PolicyRegistered(P_R, P_A, P_S, 1, 2, 3);
        vm.prank(operator);
        pprev.registerPolicy(P_R, P_A, P_S, 1, 2, 3);
        Policy memory p = policyOf(P_R);
        assertTrue(p.exists);
        assertEq(p.policyIdA, P_A);
        assertEq(p.policyIdS, P_S);
        assertEq(p.reqEscrow, 1);
        assertEq(p.minCollateral, 2);
        assertEq(p.maxCollateral, 3);
    }

    function test_RegisterPolicy_revertsForNonOperator() public {
        vm.expectRevert(NotOperator.selector);
        vm.prank(owner);
        pprev.registerPolicy(P_R, P_A, P_S, 0, 0, type(uint256).max);
    }

    function test_RegisterPolicy_bundleCannotBeChanged() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyExists.selector, RENTAL_R));
        vm.prank(operator);
        pprev.registerPolicy(RENTAL_R, P_A, P_S, 0, 0, type(uint256).max);
    }

    function test_RegisterPolicy_revertsForInvalidBundle() public {
        vm.startPrank(operator);
        vm.expectRevert(InvalidParameters.selector);
        pprev.registerPolicy(bytes32(0), P_A, P_S, 0, 0, 1);
        vm.expectRevert(InvalidParameters.selector);
        pprev.registerPolicy(P_R, bytes32(0), P_S, 0, 0, 1);
        vm.expectRevert(InvalidParameters.selector);
        pprev.registerPolicy(P_R, P_A, bytes32(0), 0, 0, 1);
        vm.expectRevert(InvalidParameters.selector);
        pprev.registerPolicy(P_R, P_R, P_S, 0, 0, 1);
        vm.expectRevert(InvalidParameters.selector);
        pprev.registerPolicy(P_R, P_A, P_R, 0, 0, 1);
        vm.expectRevert(InvalidParameters.selector);
        pprev.registerPolicy(P_R, P_A, P_A, 0, 0, 1);
        vm.expectRevert(InvalidParameters.selector);
        pprev.registerPolicy(P_R, P_A, P_S, 0, 2, 1);
        vm.stopPrank();
    }

    function test_RegisterPolicy_optionalBoundsAdmitAnyCollateralAndDeposit() public {
        vm.prank(operator);
        pprev.registerPolicy(P_R, P_A, P_S, 0, 0, type(uint256).max);
        Flow memory f;
        f.rc = registerCall(P_R, RENTAL_SHARE, owner);
        f.rc.collateral = 0;
        f.txId = doRegister(f.rc);
        ApplyCall memory c = applyCall(f, applicant);
        c.policyIdA = P_A;
        c.deposit = 0;
        doApply(c);
    }

    // ------------------------------------------------------------------ proposeNotaryVerifier

    function test_ProposeNotaryVerifier_recordsProposalAndEmits() public {
        EcdsaNotaryVerifier proposed = new EcdsaNotaryVerifier(vm.addr(ROTATED_PK));
        uint256 effectiveAt = vm.getBlockTimestamp() + ROTATION_DELAY;
        vm.expectEmit(address(pprev));
        emit NotaryVerifierProposed(address(proposed), effectiveAt);
        vm.prank(operator);
        pprev.proposeNotaryVerifier(INotaryVerifier(address(proposed)));
        assertEq(address(pprev.pendingNotaryVerifier()), address(proposed));
        assertEq(pprev.pendingEffectiveAt(), effectiveAt);
        // The current verifier and its version are unchanged.
        assertEq(address(pprev.notaryVerifier()), address(verifier));
        assertEq(pprev.notaryKeyVersion(), 1);
        assertEq(address(pprev.notaryVerifierAt(2)), address(0));
    }

    function test_ProposeNotaryVerifier_revertsForNonOperator() public {
        vm.expectRevert(NotOperator.selector);
        vm.prank(attacker);
        pprev.proposeNotaryVerifier(INotaryVerifier(attacker));
    }

    function test_ProposeNotaryVerifier_revertsForZeroAddress() public {
        vm.expectRevert(InvalidParameters.selector);
        vm.prank(operator);
        pprev.proposeNotaryVerifier(INotaryVerifier(address(0)));
    }

    function test_ProposeNotaryVerifier_revertsWhenEffectiveAtExceeds64Bits() public {
        PPREV p = new PPREV(
            operator, INotaryVerifier(address(verifier)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO, type(uint64).max
        );
        vm.expectRevert(InvalidParameters.selector);
        vm.prank(operator);
        p.proposeNotaryVerifier(INotaryVerifier(address(verifier)));
    }

    function test_ProposeNotaryVerifier_reproposalReplacesProposalAndRestartsDelay() public {
        EcdsaNotaryVerifier first = proposeNotary(ROGUE_PK);
        uint256 firstDue = pprev.pendingEffectiveAt();
        vm.warp(vm.getBlockTimestamp() + ROTATION_DELAY - 1);
        EcdsaNotaryVerifier second = proposeNotary(ROTATED_PK);
        uint256 secondDue = vm.getBlockTimestamp() + ROTATION_DELAY;
        assertEq(address(pprev.pendingNotaryVerifier()), address(second));
        assertEq(pprev.pendingEffectiveAt(), secondDue);

        // The first proposal's due time no longer activates anything.
        vm.warp(firstDue);
        vm.expectRevert(abi.encodeWithSelector(RotationNotDue.selector, secondDue));
        pprev.activateNotaryVerifier();
        vm.warp(secondDue);
        pprev.activateNotaryVerifier();
        assertEq(address(pprev.notaryVerifier()), address(second));
        assertNotEq(address(pprev.notaryVerifier()), address(first));
        assertEq(pprev.notaryKeyVersion(), 2);
    }

    // ------------------------------------------------------------------ cancelNotaryVerifierProposal

    function test_CancelNotaryVerifierProposal_clearsProposalAndEmits() public {
        EcdsaNotaryVerifier proposed = proposeNotary(ROTATED_PK);
        vm.expectEmit(address(pprev));
        emit NotaryVerifierProposalCancelled(address(proposed));
        vm.prank(operator);
        pprev.cancelNotaryVerifierProposal();
        assertEq(address(pprev.pendingNotaryVerifier()), address(0));
        assertEq(pprev.pendingEffectiveAt(), 0);

        // A cancelled proposal cannot be activated.
        vm.warp(vm.getBlockTimestamp() + ROTATION_DELAY);
        vm.expectRevert(NoPendingVerifier.selector);
        pprev.activateNotaryVerifier();
        assertEq(address(pprev.notaryVerifier()), address(verifier));
        assertEq(pprev.notaryKeyVersion(), 1);
    }

    function test_CancelNotaryVerifierProposal_revertsForNonOperator() public {
        proposeNotary(ROTATED_PK);
        vm.expectRevert(NotOperator.selector);
        vm.prank(attacker);
        pprev.cancelNotaryVerifierProposal();
    }

    function test_CancelNotaryVerifierProposal_revertsWithoutPendingProposal() public {
        vm.expectRevert(NoPendingVerifier.selector);
        vm.prank(operator);
        pprev.cancelNotaryVerifierProposal();
        // Nor once the proposal has been activated.
        rotateNotary(ROTATED_PK);
        vm.expectRevert(NoPendingVerifier.selector);
        vm.prank(operator);
        pprev.cancelNotaryVerifierProposal();
    }

    // ------------------------------------------------------------------ activateNotaryVerifier

    function test_ActivateNotaryVerifier_revertsWithoutPendingProposal() public {
        vm.expectRevert(NoPendingVerifier.selector);
        pprev.activateNotaryVerifier();
    }

    function test_ActivateNotaryVerifier_revertsOneSecondBeforeEffectiveAt() public {
        proposeNotary(ROTATED_PK);
        uint256 effectiveAt = pprev.pendingEffectiveAt();
        vm.warp(effectiveAt - 1);
        vm.expectRevert(abi.encodeWithSelector(RotationNotDue.selector, effectiveAt));
        vm.prank(attacker);
        pprev.activateNotaryVerifier();
        assertEq(pprev.notaryKeyVersion(), 1);
    }

    function test_ActivateNotaryVerifier_installsNextVersionAtEffectiveAtFromAnyCaller() public {
        EcdsaNotaryVerifier rotated = proposeNotary(ROTATED_PK);
        vm.warp(pprev.pendingEffectiveAt());
        vm.expectEmit(address(pprev));
        emit NotaryVerifierSet(address(rotated), 2);
        vm.prank(attacker);
        pprev.activateNotaryVerifier();

        assertEq(address(pprev.notaryVerifier()), address(rotated));
        assertEq(pprev.notaryKeyVersion(), 2);
        assertEq(address(pprev.notaryVerifierAt(2)), address(rotated));
        // The superseded verifier stays reachable under its version.
        assertEq(address(pprev.notaryVerifierAt(1)), address(verifier));
        // The proposal is consumed.
        assertEq(address(pprev.pendingNotaryVerifier()), address(0));
        assertEq(pprev.pendingEffectiveAt(), 0);
        vm.expectRevert(NoPendingVerifier.selector);
        pprev.activateNotaryVerifier();
    }

    function test_ActivateNotaryVerifier_versionsIncrementPerRotation() public {
        EcdsaNotaryVerifier second = rotateNotary(ROTATED_PK);
        EcdsaNotaryVerifier third = rotateNotary(ROGUE_PK);
        assertEq(pprev.notaryKeyVersion(), 3);
        assertEq(address(pprev.notaryVerifierAt(1)), address(verifier));
        assertEq(address(pprev.notaryVerifierAt(2)), address(second));
        assertEq(address(pprev.notaryVerifierAt(3)), address(third));
        assertEq(address(pprev.notaryVerifier()), address(third));
    }

    function test_ActivateNotaryVerifier_rotatesKeyForRegister() public {
        rotateNotary(ROTATED_PK);
        RegisterCall memory c = registerCall();
        bytes memory oldKeySigma = signR(xROf(c));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, oldKeySigma);
        submitRegister(c, signRWith(ROTATED_PK, c));
    }
}
