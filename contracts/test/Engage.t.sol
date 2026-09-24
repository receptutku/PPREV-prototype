// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow} from "./utils/Fixture.sol";
import {
    TxState,
    AppStatus,
    EngStatus,
    Engagement,
    Engaged,
    NotListingOwner,
    ApplicationNotPending,
    ApplicationTxMismatch,
    ListingNotOpen
} from "../src/PPREVTypes.sol";

/// @notice Acceptance conditions (i)-(iii) of Engage, Section V-F.
contract EngageTest is Fixture {
    function test_Engage_locksListingAndSetsExpiry() public {
        Flow memory f = flowApplied();
        vm.expectEmit(address(pprev));
        emit Engaged(1, f.txId, f.appId, vm.getBlockTimestamp() + TAU_LOCK);
        uint256 engId = doEngage(f);

        Engagement memory e = engagementOf(engId);
        assertEq(e.appId, f.appId);
        assertEq(e.expiresAt, vm.getBlockTimestamp() + TAU_LOCK);
        assertEq(uint8(e.status), uint8(EngStatus.Open));
        assertState(f.txId, TxState.Locked);
        assertAppStatus(f.appId, AppStatus.Engaged);
        assertEq(pprev.pendingApp(f.txId, applicant), 0);
    }

    // (i) --------------------------------------------------------------------------------------

    function test_Engage_i_acceptsListingOwner() public {
        Flow memory f = flowApplied();
        doEngage(f);
    }

    function test_Engage_i_revertsForNonOwner() public {
        Flow memory f = flowApplied();
        vm.expectRevert(NotListingOwner.selector);
        vm.prank(applicant);
        pprev.engage(f.txId, f.appId);
    }

    // (ii) -------------------------------------------------------------------------------------

    function test_Engage_ii_acceptsPendingApplication() public {
        Flow memory f = flowApplied();
        doEngage(f);
    }

    function test_Engage_ii_revertsForUnknownApplication() public {
        Flow memory f = flowApplied();
        vm.expectRevert(abi.encodeWithSelector(ApplicationNotPending.selector, 99));
        vm.prank(owner);
        pprev.engage(f.txId, 99);
    }

    function test_Engage_ii_revertsForApplicationOfOtherListing() public {
        Flow memory f1 = flowApplied();
        Flow memory f2 = flowRegistered();
        vm.expectRevert(ApplicationTxMismatch.selector);
        vm.prank(owner);
        pprev.engage(f2.txId, f1.appId);
    }

    function test_Engage_ii_revertsForEngagedApplication() public {
        Flow memory f = flowEngaged();
        lapseAndExpire(f);
        vm.expectRevert(abi.encodeWithSelector(ApplicationNotPending.selector, f.appId));
        vm.prank(owner);
        pprev.engage(f.txId, f.appId);
    }

    function test_Engage_ii_revertsForReclaimedApplication() public {
        Flow memory f = flowApplied();
        vm.prank(applicant);
        pprev.reclaim(f.appId);
        vm.expectRevert(abi.encodeWithSelector(ApplicationNotPending.selector, f.appId));
        vm.prank(owner);
        pprev.engage(f.txId, f.appId);
    }

    // (iii) ------------------------------------------------------------------------------------

    function test_Engage_iii_acceptsExpiredListing() public {
        Flow memory f = flowEngaged();
        uint256 firstExpiry = f.expiresAt;
        lapseAndExpire(f);
        nextRound(f, applicant2);
        assertState(f.txId, TxState.Locked);
        assertGt(f.expiresAt, firstExpiry);
        assertEq(engagementOf(f.engId).expiresAt, f.expiresAt);
    }

    function test_Engage_iii_revertsForLockedListing() public {
        Flow memory f = flowApplied();
        uint256 secondApp = doApply(applyCall(f, applicant2));
        doEngage(f);
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        vm.prank(owner);
        pprev.engage(f.txId, secondApp);
    }

    function test_Engage_iii_revertsForSettledListing() public {
        Flow memory f = flowApplied();
        uint256 secondApp = doApply(applyCall(f, applicant2));
        doEngage(f);
        doSettle(settleCall(f));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        vm.prank(owner);
        pprev.engage(f.txId, secondApp);
    }

    function test_Engage_iii_revertsForCancelledListing() public {
        Flow memory f = flowApplied();
        vm.prank(owner);
        pprev.cancel(f.txId);
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        vm.prank(owner);
        pprev.engage(f.txId, f.appId);
    }
}
