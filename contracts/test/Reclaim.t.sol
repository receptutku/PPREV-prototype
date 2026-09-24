// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow} from "./utils/Fixture.sol";
import {AppStatus, Reclaimed, NotDepositor, ApplicationNotPending} from "../src/PPREVTypes.sol";

/// @notice Reclaim (Section V-I): the depositor of a pending application recovers the deposit in any
/// listing state.
contract ReclaimTest is Fixture {
    function assertReclaims(uint256 appId, address depositor, uint256 txId) internal {
        uint256 before = depositor.balance;
        vm.expectEmit(address(pprev));
        emit Reclaimed(appId, txId, DEPOSIT);
        vm.prank(depositor);
        pprev.reclaim(appId);
        assertEq(depositor.balance - before, DEPOSIT);
        assertAppStatus(appId, AppStatus.Reclaimed);
        assertEq(pprev.pendingApp(txId, depositor), 0);
    }

    function test_Reclaim_acceptsInActiveListing() public {
        Flow memory f = flowApplied();
        assertReclaims(f.appId, applicant, f.txId);
    }

    function test_Reclaim_acceptsUnengagedApplicationInLockedListing() public {
        Flow memory f = flowApplied();
        uint256 other = doApply(applyCall(f, applicant2));
        doEngage(f);
        assertReclaims(other, applicant2, f.txId);
    }

    function test_Reclaim_acceptsInExpiredListing() public {
        Flow memory f = flowApplied();
        uint256 other = doApply(applyCall(f, applicant2));
        doEngage(f);
        lapseAndExpire(f);
        assertReclaims(other, applicant2, f.txId);
    }

    function test_Reclaim_acceptsInSettledListing() public {
        Flow memory f = flowApplied();
        uint256 other = doApply(applyCall(f, applicant2));
        doEngage(f);
        doSettle(settleCall(f));
        assertReclaims(other, applicant2, f.txId);
    }

    function test_Reclaim_acceptsInCancelledListing() public {
        Flow memory f = flowApplied();
        vm.prank(owner);
        pprev.cancel(f.txId);
        assertReclaims(f.appId, applicant, f.txId);
    }

    function test_Reclaim_revertsForNonDepositor() public {
        Flow memory f = flowApplied();
        vm.expectRevert(NotDepositor.selector);
        vm.prank(attacker);
        pprev.reclaim(f.appId);
    }

    function test_Reclaim_revertsForUnknownApplication() public {
        flowApplied();
        vm.expectRevert(NotDepositor.selector);
        vm.prank(applicant);
        pprev.reclaim(99);
    }

    function test_Reclaim_revertsForEngagedApplication() public {
        Flow memory f = flowEngaged();
        vm.expectRevert(abi.encodeWithSelector(ApplicationNotPending.selector, f.appId));
        vm.prank(applicant);
        pprev.reclaim(f.appId);
    }

    function test_Reclaim_revertsForReclaimedApplication() public {
        Flow memory f = flowApplied();
        vm.prank(applicant);
        pprev.reclaim(f.appId);
        vm.expectRevert(abi.encodeWithSelector(ApplicationNotPending.selector, f.appId));
        vm.prank(applicant);
        pprev.reclaim(f.appId);
    }
}
