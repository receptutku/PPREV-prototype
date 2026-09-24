// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, ApplyCall, Flow} from "./utils/Fixture.sol";
import {XA} from "./utils/NotarySigner.sol";
import {
    AppStatus,
    Application,
    Applied,
    ListingNotOpen,
    OwnerCannotApply,
    CommitmentMismatch,
    InvalidNotarySignature,
    NonceConsumed,
    AttestationFromFuture,
    AttestationExpired,
    PendingApplicationExists,
    InsufficientDeposit
} from "../src/PPREVTypes.sol";

/// @notice Acceptance conditions A(a)-A(h) of Section V-E.
contract ApplyTest is Fixture {
    function test_Apply_recordsApplicationAndEmits() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        bytes memory sigma = signA(xAOf(c));
        vm.expectEmit(address(pprev));
        emit Applied(1, f.txId, applicant, c.cB, DEPOSIT);
        uint256 appId = submitApply(c, sigma);

        Application memory a = applicationOf(appId);
        assertEq(a.txId, f.txId);
        assertEq(a.depositor, applicant);
        assertEq(uint8(a.status), uint8(AppStatus.Pending));
        assertEq(a.deposit, DEPOSIT);
        assertEq(a.cB, c.cB);
        assertEq(pprev.pendingApp(f.txId, applicant), appId);
        assertTrue(pprev.consumed(c.eta));
        assertEq(address(pprev).balance, COLLATERAL + DEPOSIT);
    }

    // A(a) -------------------------------------------------------------------------------------

    function test_A_a_acceptsActiveListing() public {
        Flow memory f = flowRegistered();
        doApply(applyCall(f, applicant));
    }

    function test_A_a_acceptsExpiredListing() public {
        Flow memory f = flowEngaged();
        lapseAndExpire(f);
        doApply(applyCall(f, applicant2));
    }

    function test_A_a_revertsForUnknownListing() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.txId = 99;
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, 99));
        submitApply(c, sigma);
    }

    function test_A_a_revertsForLockedListing() public {
        Flow memory f = flowEngaged();
        ApplyCall memory c = applyCall(f, applicant2);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        submitApply(c, sigma);
    }

    function test_A_a_revertsForSettledListing() public {
        Flow memory f = flowEngaged();
        doSettle(settleCall(f));
        ApplyCall memory c = applyCall(f, applicant2);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        submitApply(c, sigma);
    }

    function test_A_a_revertsForCancelledListing() public {
        Flow memory f = flowRegistered();
        vm.prank(owner);
        pprev.cancel(f.txId);
        ApplyCall memory c = applyCall(f, applicant);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        submitApply(c, sigma);
    }

    function test_A_a_revertsForExhaustedListing() public {
        Flow memory f = flowEngaged();
        lapseAndExpire(f);
        nextRound(f, applicant2);
        lapseAndExpire(f);
        nextRound(f, applicant);
        lapseAndExpire(f);
        ApplyCall memory c = applyCall(f, applicant2);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        submitApply(c, sigma);
    }

    // A(b) -------------------------------------------------------------------------------------

    function test_A_b_acceptsNonOwner() public {
        Flow memory f = flowRegistered();
        doApply(applyCall(f, applicant));
    }

    function test_A_b_revertsForListingOwner() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, owner);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(OwnerCannotApply.selector);
        submitApply(c, sigma);
    }

    // A(c) -------------------------------------------------------------------------------------

    function test_A_c_acceptsRegisteredTxData() public {
        Flow memory f = flowRegistered();
        doApply(applyCall(f, applicant));
    }

    function test_A_c_revertsWhenTxDataAltered() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.txData.amount -= 1;
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitApply(c, sigma);
    }

    function test_A_c_revertsWhenSaltAltered() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.r = next("other salt");
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitApply(c, sigma);
    }

    // A(d) -------------------------------------------------------------------------------------

    function test_A_d_acceptsNotarySignature() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        submitApply(c, signA(xAOf(c)));
    }

    function test_A_d_revertsForWrongSigner() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        bytes memory sigma = signDigest(ROGUE_PK, digest(structHashA(xAOf(c))));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(c, sigma);
    }

    function test_A_d_revertsForOtherSubmitter() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        bytes memory sigma = signA(xAOf(c));
        c.caller = attacker;
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(c, sigma);
    }

    function test_A_d_revertsForOtherPhaseTag() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        bytes memory sigma = signUnderTypehash(typehashS(), encodeDataA(xAOf(c)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(c, sigma);
    }

    function test_A_d_revertsForOtherListing() public {
        // A signature for listing 1 presented on listing 2 with identical txData and salt handling.
        Flow memory f1 = flowRegistered();
        Flow memory f2 = flowRegistered();
        ApplyCall memory forFirst = applyCall(f1, applicant);
        bytes memory sigma = signA(xAOf(forFirst));
        ApplyCall memory c = applyCall(f2, applicant);
        c.eta = forFirst.eta;
        c.cB = forFirst.cB;
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(c, sigma);
    }

    function test_A_d_revertsWhenSignedCbDiffers() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        XA memory x = xAOf(c);
        x.cB = cBOf(attacker);
        bytes memory sigma = signA(x);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(c, sigma);
    }

    function test_A_d_revertsWhenSignedUnderRegistrationPolicy() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        XA memory x = xAOf(c);
        x.policyId = RENTAL_R;
        bytes memory sigma = signA(x);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitApply(c, sigma);
    }

    // A(e) -------------------------------------------------------------------------------------

    function test_A_e_acceptsFreshNonce() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        doApply(c);
        assertTrue(pprev.consumed(c.eta));
    }

    function test_A_e_revertsForConsumedNonce() public {
        Flow memory f = flowRegistered();
        ApplyCall memory first = applyCall(f, applicant);
        doApply(first);
        ApplyCall memory c = applyCall(f, applicant2);
        c.eta = first.eta;
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(NonceConsumed.selector, first.eta));
        submitApply(c, sigma);
    }

    // A(f) -------------------------------------------------------------------------------------

    function test_A_f_acceptsAtAttestationTime() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.tAtt = now64();
        doApply(c);
    }

    function test_A_f_acceptsAtWindowEnd() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.tAtt = uint64(vm.getBlockTimestamp() - DELTA);
        doApply(c);
    }

    function test_A_f_revertsAfterWindow() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.tAtt = uint64(vm.getBlockTimestamp() - DELTA - 1);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(AttestationExpired.selector, c.tAtt));
        submitApply(c, sigma);
    }

    function test_A_f_revertsForFutureAttestation() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.tAtt = uint64(vm.getBlockTimestamp() + 1);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(AttestationFromFuture.selector, c.tAtt));
        submitApply(c, sigma);
    }

    // A(g) -------------------------------------------------------------------------------------

    function test_A_g_acceptsFirstApplication() public {
        Flow memory f = flowRegistered();
        assertEq(pprev.pendingApp(f.txId, applicant), 0);
        doApply(applyCall(f, applicant));
    }

    function test_A_g_revertsForSecondPendingApplication() public {
        Flow memory f = flowRegistered();
        uint256 firstApp = doApply(applyCall(f, applicant));
        ApplyCall memory c = applyCall(f, applicant);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(PendingApplicationExists.selector, firstApp));
        submitApply(c, sigma);
    }

    function test_A_g_acceptsAgainAfterReclaim() public {
        Flow memory f = flowRegistered();
        uint256 firstApp = doApply(applyCall(f, applicant));
        vm.prank(applicant);
        pprev.reclaim(firstApp);
        uint256 secondApp = doApply(applyCall(f, applicant));
        assertEq(pprev.pendingApp(f.txId, applicant), secondApp);
    }

    function test_A_g_acceptsOtherApplicants() public {
        Flow memory f = flowRegistered();
        doApply(applyCall(f, applicant));
        doApply(applyCall(f, applicant2));
    }

    // A(h) -------------------------------------------------------------------------------------

    function test_A_h_acceptsRequiredEscrow() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.deposit = REQ_ESCROW;
        doApply(c);
    }

    function test_A_h_revertsBelowRequiredEscrow() public {
        Flow memory f = flowRegistered();
        ApplyCall memory c = applyCall(f, applicant);
        c.deposit = REQ_ESCROW - 1;
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(InsufficientDeposit.selector, c.deposit));
        submitApply(c, sigma);
    }
}
