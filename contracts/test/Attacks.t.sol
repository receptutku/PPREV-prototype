// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow, RegisterCall, ApplyCall, SettleCall} from "./utils/Fixture.sol";
import {XA, XS} from "./utils/NotarySigner.sol";
import {PPREV} from "../src/PPREV.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {
    TxState,
    InvalidNotarySignature,
    NonceConsumed,
    AttestationExpired,
    CommitmentMismatch,
    NotListingOwner,
    NotLocked,
    LockWindowElapsed,
    EngagementNotOpen,
    OwnerCannotApply
} from "../src/PPREVTypes.sol";

/// @notice The five attack classes of Section IV, each played against the contract. Table VI lists the
/// enforcing conditions: P1 freshness, P2 transaction binding, P3 phase binding, P4 settlement
/// integrity, P5 sender binding. Off-chain parts of Table VI are not exercised here.
contract AttacksTest is Fixture {
    // ------------------------------------------------------------------ P1 stale evidence reuse

    function test_P1_staleEvidenceRejectedInEveryPhase() public {
        // Register: evidence attested before the window.
        RegisterCall memory rc = registerCall();
        bytes memory sigmaR = signR(xROf(rc));
        vm.warp(vm.getBlockTimestamp() + DELTA + 1);
        vm.expectRevert(abi.encodeWithSelector(AttestationExpired.selector, rc.tAtt));
        submitRegister(rc, sigmaR);

        // Apply
        Flow memory f = flowRegistered();
        ApplyCall memory ac = applyCall(f, applicant);
        bytes memory sigmaA = signA(xAOf(ac));
        vm.warp(vm.getBlockTimestamp() + DELTA + 1);
        vm.expectRevert(abi.encodeWithSelector(AttestationExpired.selector, ac.tAtt));
        submitApply(ac, sigmaA);

        // Settle
        f.ac = applyCall(f, applicant);
        f.appId = doApply(f.ac);
        doEngage(f);
        SettleCall memory sc = settleCall(f);
        bytes memory sigmaS = signS(xSOf(sc));
        vm.warp(vm.getBlockTimestamp() + DELTA + 1);
        vm.expectRevert(abi.encodeWithSelector(AttestationExpired.selector, sc.tAtt));
        submitSettle(sc, sigmaS);
    }

    // ------------------------------------------------------------------ P2 cross-transaction replay

    function test_P2_acceptedPayloadCannotBeReplayed() public {
        RegisterCall memory rc = registerCall();
        bytes memory sigmaR = signR(xROf(rc));
        submitRegister(rc, sigmaR);
        vm.expectRevert(abi.encodeWithSelector(NonceConsumed.selector, rc.eta));
        submitRegister(rc, sigmaR);
    }

    function test_P2_nonceIsGlobalAcrossPhases() public {
        Flow memory f = flowRegistered();
        ApplyCall memory ac = applyCall(f, applicant);
        ac.eta = f.rc.eta;
        bytes memory sigmaA = signA(xAOf(ac));
        vm.expectRevert(abi.encodeWithSelector(NonceConsumed.selector, f.rc.eta));
        submitApply(ac, sigmaA);
    }

    function test_P2_signatureBoundToDeployment() public {
        PPREV other = new PPREV(operator, INotaryVerifier(address(verifier)), DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO);
        vm.prank(operator);
        other.registerPolicy(RENTAL_R, RENTAL_A, RENTAL_S, REQ_ESCROW, MIN_COLLATERAL, MAX_COLLATERAL);
        RegisterCall memory rc = registerCall();
        bytes memory sigmaForPprev = signR(xROf(rc));
        vm.expectRevert(InvalidNotarySignature.selector);
        vm.prank(owner);
        other.register{value: rc.collateral}(rc.cTx, rc.txData, rc.policyIdR, rc.r, sigmaForPprev, rc.eta, rc.tAtt);
        // The same payload is accepted by the deployment it was signed for.
        submitRegister(rc, sigmaForPprev);
    }

    function test_P2_signatureBoundToChain() public {
        RegisterCall memory rc = registerCall();
        bytes memory sigmaThisChain = signR(xROf(rc));
        uint256 originalChain = vm.getChainId();
        vm.chainId(originalChain + 1);
        // The contract recomputes its domain separator for the new chain id.
        assertEq(pprev.domainSeparator(), domainSeparatorFor(originalChain + 1, address(pprev)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(rc, sigmaThisChain);
        submitRegister(rc, signR(xROf(rc)));
    }

    // ------------------------------------------------------------------ P3 cross-phase substitution

    function test_P3_signatureOfOnePhaseRejectedInAnother() public {
        Flow memory f = flowRegistered();
        bytes memory sigmaR = signR(xROf(f.rc));
        f.ac = applyCall(f, applicant);

        // Registration signature presented to Apply.
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(f.ac, sigmaR);

        // Apply fields signed under the Register and Settle tags.
        bytes memory wrongTag = signUnderTypehash(typehashR(), encodeDataA(xAOf(f.ac)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(f.ac, wrongTag);
        wrongTag = signUnderTypehash(typehashS(), encodeDataA(xAOf(f.ac)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(f.ac, wrongTag);

        // Registration and Apply signatures presented to Settle.
        bytes memory sigmaA = signA(xAOf(f.ac));
        f.appId = submitApply(f.ac, sigmaA);
        doEngage(f);
        SettleCall memory sc = settleCall(f);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(sc, sigmaR);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(sc, sigmaA);
        wrongTag = signUnderTypehash(typehashA(), encodeDataS(xSOf(sc)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(sc, wrongTag);
        doSettle(sc);
    }

    // ------------------------------------------------------------------ P4 unauthorised settlement

    function test_P4_unauthorisedSettlementAttempts() public {
        Flow memory f = flowEngaged(SALE_R, SALE_SHARE);
        SettleCall memory c;
        bytes memory sigma;

        // The counterparty cannot settle, even with a signature bound to itself.
        c = settleCall(f);
        c.caller = applicant;
        sigma = signS(xSOf(c));
        vm.expectRevert(NotListingOwner.selector);
        submitSettle(c, sigma);

        // The owner cannot raise the settlement share after the counterparty is locked in.
        c = settleCall(f);
        c.txData.settlementShare = 10_000;
        sigma = signS(xSOf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitSettle(c, sigma);

        // A settlement record naming another identity than c_B yields no valid signature.
        c = settleCall(f);
        {
            XS memory x = xSOf(c);
            x.cB = cBOf(attacker);
            sigma = signS(x);
        }
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(c, sigma);

        // Settlement after the lock window fails; expiration pays out once and cannot be repeated.
        vm.warp(f.expiresAt + 1);
        c = settleCall(f);
        sigma = signS(xSOf(c));
        vm.expectRevert(LockWindowElapsed.selector);
        submitSettle(c, sigma);
        pprev.expire(f.engId);
        vm.expectRevert(abi.encodeWithSelector(EngagementNotOpen.selector, f.engId));
        pprev.expire(f.engId);

        // A settlement of the expired engagement is rejected once the listing is no longer locked.
        c = settleCall(f);
        sigma = signS(xSOf(c));
        vm.expectRevert(abi.encodeWithSelector(NotLocked.selector, f.txId));
        submitSettle(c, sigma);
    }

    function test_P4_selfApplicationRejected() public {
        Flow memory g = flowRegistered();
        ApplyCall memory self = applyCall(g, owner);
        bytes memory sigmaSelf = signA(xAOf(self));
        vm.expectRevert(OwnerCannotApply.selector);
        submitApply(self, sigmaSelf);
    }

    function test_P4_doubleSettlementRejected() public {
        Flow memory f = flowEngaged();
        doSettle(settleCall(f));
        assertState(f.txId, TxState.Settled);
        SettleCall memory again = settleCall(f);
        bytes memory sigma = signS(xSOf(again));
        vm.expectRevert(abi.encodeWithSelector(NotLocked.selector, f.txId));
        submitSettle(again, sigma);
    }

    // ------------------------------------------------------------------ P5 submission front-running

    function test_P5_frontRunRegisterFailsAndHonestSubmissionSucceeds() public {
        RegisterCall memory rc = registerCall();
        bytes memory sigma = signR(xROf(rc));
        RegisterCall memory stolen = rc;
        stolen.caller = attacker;
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(stolen, sigma);
        assertFalse(pprev.consumed(rc.eta));
        rc.caller = owner;
        submitRegister(rc, sigma);
    }

    function test_P5_frontRunApplyFailsAndHonestSubmissionSucceeds() public {
        Flow memory f = flowRegistered();
        ApplyCall memory ac = applyCall(f, applicant);
        bytes memory sigma = signA(xAOf(ac));
        ac.caller = attacker;
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(ac, sigma);
        assertFalse(pprev.consumed(ac.eta));
        ac.caller = applicant;
        submitApply(ac, sigma);
    }

    function test_P5_frontRunSettleFailsAndHonestSubmissionSucceeds() public {
        Flow memory f = flowEngaged();
        SettleCall memory sc = settleCall(f);
        bytes memory sigma = signS(xSOf(sc));
        sc.caller = attacker;
        // S(b) fires before the signature check; the sender binding is defence in depth here.
        vm.expectRevert(NotListingOwner.selector);
        submitSettle(sc, sigma);
        sc.caller = owner;
        submitSettle(sc, sigma);
        assertState(f.txId, TxState.Settled);
    }
}
