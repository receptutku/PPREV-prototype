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
    NotOperator,
    InvalidParameters,
    PolicyExists,
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
        assertEq(address(pprev.notaryVerifier()), address(verifier));
        assertEq(pprev.nextTxId(), 1);
        assertEq(pprev.nextAppId(), 1);
        assertEq(pprev.nextEngId(), 1);
        assertEq(pprev.domainSeparator(), domainSeparatorFor(vm.getChainId(), address(pprev)));
    }

    function test_Constructor_revertsForInvalidParameters() public {
        INotaryVerifier v = INotaryVerifier(address(verifier));
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(address(0), v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, INotaryVerifier(address(0)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, 0, TAU_LOCK, MAX_EXPIRATIONS, RHO);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, 0, MAX_EXPIRATIONS, RHO);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, TAU_LOCK, 0, RHO);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, 0);
        vm.expectRevert(InvalidParameters.selector);
        new PPREV(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, 10_000);
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

    // ------------------------------------------------------------------ setNotaryVerifier

    function test_SetNotaryVerifier_rotatesKey() public {
        EcdsaNotaryVerifier rotated = new EcdsaNotaryVerifier(vm.addr(ROGUE_PK));
        vm.expectEmit(address(pprev));
        emit NotaryVerifierSet(address(rotated));
        vm.prank(operator);
        pprev.setNotaryVerifier(INotaryVerifier(address(rotated)));

        RegisterCall memory c = registerCall();
        bytes memory oldKeySigma = signR(xROf(c));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, oldKeySigma);

        bytes memory newKeySigma = signDigest(ROGUE_PK, digest(structHashR(xROf(c))));
        submitRegister(c, newKeySigma);
    }

    function test_SetNotaryVerifier_revertsForNonOperator() public {
        vm.expectRevert(NotOperator.selector);
        vm.prank(attacker);
        pprev.setNotaryVerifier(INotaryVerifier(attacker));
    }

    function test_SetNotaryVerifier_revertsForZeroAddress() public {
        vm.expectRevert(InvalidParameters.selector);
        vm.prank(operator);
        pprev.setNotaryVerifier(INotaryVerifier(address(0)));
    }
}
