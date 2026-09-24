// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow, SettleCall} from "./utils/Fixture.sol";
import {
    TxState,
    EngStatus,
    Expired,
    EngagementNotOpen,
    LockWindowNotElapsed,
    LockWindowElapsed
} from "../src/PPREVTypes.sol";

/// @notice Acceptance conditions E(a)-E(c) of Section V-H and the compounding slash. The negative
/// case of E(b) is unreachable through external calls and is in WhiteBox.t.sol.
contract ExpireTest is Fixture {
    function test_Expire_compensatesCounterparty() public {
        Flow memory f = flowEngaged();
        uint256 applicantBefore = applicant.balance;
        uint256 compensation = COLLATERAL - COLLATERAL * RHO / 10_000;
        vm.warp(f.expiresAt + 1);
        vm.expectEmit(address(pprev));
        emit Expired(f.engId, f.txId, compensation, 1, false, 0);
        pprev.expire(f.engId);

        assertState(f.txId, TxState.Expired);
        assertEngStatus(f.engId, EngStatus.Expired);
        assertEq(applicant.balance - applicantBefore, DEPOSIT + compensation);
        assertEq(listingOf(f.txId).collateral, COLLATERAL * RHO / 10_000);
        assertEq(listingOf(f.txId).expirations, 1);
        assertEq(address(pprev).balance, COLLATERAL * RHO / 10_000);
    }

    function test_Expire_callableByAnyone() public {
        Flow memory f = flowEngaged();
        vm.warp(f.expiresAt + 1);
        vm.prank(attacker);
        pprev.expire(f.engId);
        assertState(f.txId, TxState.Expired);
    }

    function test_Expire_slashCompoundsAndExhaustingExpirationCancels() public {
        Flow memory f = flowEngaged();
        address[3] memory counterparties = [applicant, applicant2, applicant];
        uint256 remaining = COLLATERAL;
        uint256 ownerBefore = owner.balance;
        for (uint256 k = 1; k <= MAX_EXPIRATIONS; ++k) {
            if (k > 1) nextRound(f, counterparties[k - 1]);
            uint256 counterpartyBefore = counterparties[k - 1].balance;
            uint256 surviving = remaining * RHO / 10_000;
            lapseAndExpire(f);
            assertEq(counterparties[k - 1].balance - counterpartyBefore, DEPOSIT + remaining - surviving);
            remaining = surviving;
        }
        // After maxExpirations = 3 rounds the owner keeps rho^3 of the collateral, returned in the
        // exhausting call itself.
        assertState(f.txId, TxState.Cancelled);
        assertEq(remaining, COLLATERAL / 8);
        assertEq(owner.balance - ownerBefore, remaining);
        assertEq(listingOf(f.txId).collateral, 0);
        assertEq(listingOf(f.txId).expirations, MAX_EXPIRATIONS);
        assertEq(address(pprev).balance, 0);
    }

    function test_Expire_settleAndExpireWindowsMeetWithoutOverlap() public {
        Flow memory f = flowEngaged();
        vm.warp(f.expiresAt);
        vm.expectRevert(LockWindowNotElapsed.selector);
        pprev.expire(f.engId);
        uint256 snapshot = vm.snapshotState();
        doSettle(settleCall(f));
        vm.revertToState(snapshot);

        vm.warp(f.expiresAt + 1);
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signS(xSOf(c));
        vm.expectRevert(LockWindowElapsed.selector);
        submitSettle(c, sigma);
        pprev.expire(f.engId);
    }

    // E(a) -------------------------------------------------------------------------------------

    function test_E_a_acceptsOpenEngagement() public {
        Flow memory f = flowEngaged();
        assertEngStatus(f.engId, EngStatus.Open);
        lapseAndExpire(f);
    }

    function test_E_a_revertsForUnknownEngagement() public {
        flowEngaged();
        vm.expectRevert(abi.encodeWithSelector(EngagementNotOpen.selector, 99));
        pprev.expire(99);
    }

    function test_E_a_revertsForSettledEngagement() public {
        Flow memory f = flowEngaged();
        doSettle(settleCall(f));
        vm.warp(f.expiresAt + 1);
        vm.expectRevert(abi.encodeWithSelector(EngagementNotOpen.selector, f.engId));
        pprev.expire(f.engId);
    }

    function test_E_a_revertsForExpiredEngagement() public {
        Flow memory f = flowEngaged();
        lapseAndExpire(f);
        vm.expectRevert(abi.encodeWithSelector(EngagementNotOpen.selector, f.engId));
        pprev.expire(f.engId);
    }

    function test_E_a_revertsForPreviousRoundEngagement() public {
        // After re-engagement the listing is LOCKED again and now > expiresAt of round 1, so E(b) and
        // E(c) hold for the round-1 engagement; E(a) rejects it (Section V-H).
        Flow memory f = flowEngaged();
        uint256 oldEngId = f.engId;
        lapseAndExpire(f);
        nextRound(f, applicant2);
        vm.warp(f.expiresAt + 1);
        vm.expectRevert(abi.encodeWithSelector(EngagementNotOpen.selector, oldEngId));
        pprev.expire(oldEngId);
    }

    // E(b) -------------------------------------------------------------------------------------

    function test_E_b_acceptsLockedListing() public {
        Flow memory f = flowEngaged();
        assertState(f.txId, TxState.Locked);
        lapseAndExpire(f);
    }

    // E(c) -------------------------------------------------------------------------------------

    function test_E_c_acceptsAfterExpiresAt() public {
        Flow memory f = flowEngaged();
        vm.warp(f.expiresAt + 1);
        pprev.expire(f.engId);
    }

    function test_E_c_revertsAtExpiresAt() public {
        Flow memory f = flowEngaged();
        vm.warp(f.expiresAt);
        vm.expectRevert(LockWindowNotElapsed.selector);
        pprev.expire(f.engId);
    }

    function test_E_c_revertsBeforeExpiresAt() public {
        Flow memory f = flowEngaged();
        vm.expectRevert(LockWindowNotElapsed.selector);
        pprev.expire(f.engId);
    }
}
