// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow, SettleCall} from "./utils/Fixture.sol";
import {XS} from "./utils/NotarySigner.sol";
import {
    TxState,
    EngStatus,
    Settled,
    UnknownEngagement,
    NotListingOwner,
    NotLocked,
    CommitmentMismatch,
    InvalidNotarySignature,
    NonceConsumed,
    AttestationFromFuture,
    AttestationExpired,
    LockWindowElapsed
} from "../src/PPREVTypes.sol";

/// @notice Acceptance conditions S(a)-S(h) of Section V-G.
contract SettleTest is Fixture {
    function test_Settle_rentalReturnsDepositAndCollateral() public {
        Flow memory f = flowEngaged(RENTAL_R, RENTAL_SHARE);
        uint256 ownerBefore = owner.balance;
        uint256 applicantBefore = applicant.balance;
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signS(xSOf(c));
        vm.expectEmit(address(pprev));
        emit Settled(f.engId, f.txId, COLLATERAL, DEPOSIT);
        submitSettle(c, sigma);

        assertState(f.txId, TxState.Settled);
        assertEngStatus(f.engId, EngStatus.Settled);
        assertEq(owner.balance - ownerBefore, COLLATERAL);
        assertEq(applicant.balance - applicantBefore, DEPOSIT);
        assertEq(listingOf(f.txId).collateral, 0);
        assertEq(address(pprev).balance, 0);
        assertTrue(pprev.consumed(c.eta));
    }

    function test_Settle_salePaysShareFixedInTxData() public {
        Flow memory f = flowEngaged(SALE_R, SALE_SHARE);
        uint256 ownerBefore = owner.balance;
        uint256 applicantBefore = applicant.balance;
        doSettle(settleCall(f));
        uint256 share = DEPOSIT * SALE_SHARE / 10_000;
        assertEq(owner.balance - ownerBefore, COLLATERAL + share);
        assertEq(applicant.balance - applicantBefore, DEPOSIT - share);
        assertEq(address(pprev).balance, 0);
    }

    // S(a) -------------------------------------------------------------------------------------

    function test_S_a_acceptsExistingEngagement() public {
        Flow memory f = flowEngaged();
        doSettle(settleCall(f));
    }

    function test_S_a_revertsForUnknownEngagement() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        c.engId = 99;
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(abi.encodeWithSelector(UnknownEngagement.selector, 99));
        submitSettle(c, sigma);
    }

    // S(b) -------------------------------------------------------------------------------------

    function test_S_b_acceptsListingOwner() public {
        Flow memory f = flowEngaged();
        doSettle(settleCall(f));
    }

    function test_S_b_revertsForCounterparty() public {
        // Even with a notary signature bound to the counterparty's own address.
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        c.caller = applicant;
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(NotListingOwner.selector);
        submitSettle(c, sigma);
    }

    function test_S_b_revertsBeforeSignatureCheck() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        c.caller = attacker;
        vm.expectRevert(NotListingOwner.selector);
        submitSettle(c, hex"00");
    }

    // S(c) -------------------------------------------------------------------------------------

    function test_S_c_acceptsLockedListing() public {
        Flow memory f = flowEngaged();
        assertState(f.txId, TxState.Locked);
        doSettle(settleCall(f));
    }

    function test_S_c_revertsForExpiredListing() public {
        Flow memory f = flowEngaged();
        lapseAndExpire(f);
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(abi.encodeWithSelector(NotLocked.selector, f.txId));
        submitSettle(c, sigma);
    }

    function test_S_c_revertsForDoubleSettlement() public {
        Flow memory f = flowEngaged();
        doSettle(settleCall(f));
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(abi.encodeWithSelector(NotLocked.selector, f.txId));
        submitSettle(c, sigma);
    }

    // S(d) -------------------------------------------------------------------------------------

    function test_S_d_acceptsRegisteredTxData() public {
        Flow memory f = flowEngaged(SALE_R, SALE_SHARE);
        doSettle(settleCall(f));
    }

    function test_S_d_revertsWhenShareRaised() public {
        // The owner cannot change the settlement terms after the applicant is locked in.
        Flow memory f = flowEngaged(SALE_R, SALE_SHARE);
        SettleCall memory c = settleCall(f);
        c.txData.settlementShare = 10_000;
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitSettle(c, sigma);
    }

    function test_S_d_revertsWhenSaltAltered() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        c.r = next("other salt");
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitSettle(c, sigma);
    }

    // S(e) -------------------------------------------------------------------------------------

    function test_S_e_acceptsNotarySignature() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        submitSettle(c, signS(xSOf(c)));
    }

    function test_S_e_revertsForWrongSigner() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signDigest(ROGUE_PK, digest(structHashS(xSOf(c))));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(c, sigma);
    }

    function test_S_e_revertsForOtherPhaseTag() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signUnderTypehash(typehashA(), encodeDataS(xSOf(c)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(c, sigma);
    }

    function test_S_e_revertsForOtherEngagement() public {
        // A settlement signature for one listing's engagement presented for another's.
        Flow memory f1 = flowEngaged();
        Flow memory f2 = flowRegistered();
        f2.ac = applyCall(f2, applicant2);
        f2.appId = doApply(f2.ac);
        doEngage(f2);
        SettleCall memory forFirst = settleCall(f1);
        bytes memory sigma = signS(xSOf(forFirst));
        SettleCall memory c = settleCall(f2);
        c.eta = forFirst.eta;
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(c, sigma);
    }

    function test_S_e_revertsWhenSignedCbDiffers() public {
        // The record must name the identity committed at Apply; c_B comes from the application record.
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        XS memory x = xSOf(c);
        x.cB = cBOf(attacker);
        bytes memory sigma = signS(x);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(c, sigma);
    }

    function test_S_e_revertsWhenSignedExpiryDiffers() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        XS memory x = xSOf(c);
        x.expiresAt += 1;
        bytes memory sigma = signS(x);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(c, sigma);
    }

    function test_S_e_revertsWhenSignedForOtherSubmitter() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        XS memory x = xSOf(c);
        x.submitter = attacker;
        bytes memory sigma = signS(x);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitSettle(c, sigma);
    }

    // S(f) -------------------------------------------------------------------------------------

    function test_S_f_acceptsFreshNonce() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        doSettle(c);
        assertTrue(pprev.consumed(c.eta));
    }

    function test_S_f_revertsForConsumedNonce() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        c.eta = f.ac.eta;
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(abi.encodeWithSelector(NonceConsumed.selector, f.ac.eta));
        submitSettle(c, sigma);
    }

    // S(g) -------------------------------------------------------------------------------------

    function test_S_g_acceptsAtAttestationTime() public {
        Flow memory f = flowEngaged();
        vm.warp(vm.getBlockTimestamp() + 1 days);
        SettleCall memory c = settleCall(f);
        c.tAtt = now64();
        doSettle(c);
    }

    function test_S_g_acceptsAtWindowEnd() public {
        Flow memory f = flowEngaged();
        vm.warp(vm.getBlockTimestamp() + 1 days);
        SettleCall memory c = settleCall(f);
        c.tAtt = uint64(vm.getBlockTimestamp() - DELTA);
        doSettle(c);
    }

    function test_S_g_revertsAfterWindow() public {
        Flow memory f = flowEngaged();
        vm.warp(vm.getBlockTimestamp() + 1 days);
        SettleCall memory c = settleCall(f);
        c.tAtt = uint64(vm.getBlockTimestamp() - DELTA - 1);
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(abi.encodeWithSelector(AttestationExpired.selector, c.tAtt));
        submitSettle(c, sigma);
    }

    function test_S_g_revertsForFutureAttestation() public {
        Flow memory f = flowEngaged();
        SettleCall memory c = settleCall(f);
        c.tAtt = uint64(vm.getBlockTimestamp() + 1);
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(abi.encodeWithSelector(AttestationFromFuture.selector, c.tAtt));
        submitSettle(c, sigma);
    }

    // S(h) -------------------------------------------------------------------------------------

    function test_S_h_acceptsAtExpiresAt() public {
        Flow memory f = flowEngaged();
        vm.warp(f.expiresAt);
        doSettle(settleCall(f));
    }

    function test_S_h_revertsAfterExpiresAt() public {
        Flow memory f = flowEngaged();
        vm.warp(f.expiresAt + 1);
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(LockWindowElapsed.selector);
        submitSettle(c, sigma);
    }

    function test_S_h_revertsForPreviousRoundEngagement() public {
        // Round 1 lapses and is expired; round 2 locks the listing again. A fresh, correctly signed
        // settlement of the round-1 engagement passes S(a)-S(g) and is rejected by S(h).
        Flow memory f = flowEngaged();
        uint256 oldEngId = f.engId;
        uint256 oldExpiresAt = f.expiresAt;
        bytes32 oldCb = f.ac.cB;
        lapseAndExpire(f);
        nextRound(f, applicant2);
        assertState(f.txId, TxState.Locked);

        SettleCall memory c = settleCall(f);
        c.engId = oldEngId;
        c.expiresAt = oldExpiresAt;
        c.cB = oldCb;
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(LockWindowElapsed.selector);
        submitSettle(c, sigma);
    }
}
