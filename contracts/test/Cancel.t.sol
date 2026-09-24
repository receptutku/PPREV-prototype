// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow} from "./utils/Fixture.sol";
import {TxState, Cancelled, NotListingOwner, ListingNotOpen} from "../src/PPREVTypes.sol";

/// @notice Cancel (Section V-J): the owner withdraws a listing while no engagement is pending.
contract CancelTest is Fixture {
    function test_Cancel_acceptsActiveListing() public {
        Flow memory f = flowRegistered();
        uint256 before = owner.balance;
        vm.expectEmit(address(pprev));
        emit Cancelled(f.txId, COLLATERAL);
        vm.prank(owner);
        pprev.cancel(f.txId);
        assertState(f.txId, TxState.Cancelled);
        assertEq(owner.balance - before, COLLATERAL);
        assertEq(listingOf(f.txId).collateral, 0);
        assertEq(address(pprev).balance, 0);
    }

    function test_Cancel_acceptsExpiredListingWithRemainingCollateral() public {
        Flow memory f = flowEngaged();
        lapseAndExpire(f);
        uint256 remaining = COLLATERAL * RHO / 10_000;
        uint256 before = owner.balance;
        vm.prank(owner);
        pprev.cancel(f.txId);
        assertState(f.txId, TxState.Cancelled);
        assertEq(owner.balance - before, remaining);
        assertEq(address(pprev).balance, 0);
    }

    function test_Cancel_keepsPendingDepositsReclaimable() public {
        Flow memory f = flowApplied();
        vm.prank(owner);
        pprev.cancel(f.txId);
        assertEq(address(pprev).balance, DEPOSIT);
        vm.prank(applicant);
        pprev.reclaim(f.appId);
        assertEq(address(pprev).balance, 0);
    }

    function test_Cancel_revertsForNonOwner() public {
        Flow memory f = flowRegistered();
        vm.expectRevert(NotListingOwner.selector);
        vm.prank(attacker);
        pprev.cancel(f.txId);
    }

    function test_Cancel_revertsForUnknownListing() public {
        vm.expectRevert(NotListingOwner.selector);
        vm.prank(owner);
        pprev.cancel(99);
    }

    function test_Cancel_revertsWhileEngagementPending() public {
        Flow memory f = flowEngaged();
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        vm.prank(owner);
        pprev.cancel(f.txId);
    }

    function test_Cancel_revertsForSettledListing() public {
        Flow memory f = flowEngaged();
        doSettle(settleCall(f));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        vm.prank(owner);
        pprev.cancel(f.txId);
    }

    function test_Cancel_revertsForCancelledListing() public {
        Flow memory f = flowRegistered();
        vm.prank(owner);
        pprev.cancel(f.txId);
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        vm.prank(owner);
        pprev.cancel(f.txId);
    }
}
