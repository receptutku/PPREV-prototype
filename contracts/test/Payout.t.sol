// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Flow} from "./utils/Fixture.sol";
import {ActorFlows} from "./utils/ActorFlows.sol";
import {Actor} from "./mocks/Actor.sol";
import {PPREV} from "../src/PPREV.sol";
import {TxState, EngStatus, PayoutCredited} from "../src/PPREVTypes.sol";

/// @notice Payout rule of Section V-A: a payout that its recipient does not accept is credited to
/// the recipient instead of reverting the algorithm, on every terminal path.
contract PayoutTest is ActorFlows {
    // ------------------------------------------------------------------ Settle, owner refuses

    function settleOwnerRefusal(Actor.Mode mode) internal {
        Flow memory f = actorOwnerEngaged();
        actor.setMode(mode);
        uint256 applicantBefore = applicant.balance;
        vm.expectEmit(address(pprev));
        emit PayoutCredited(address(actor), COLLATERAL);
        actorSettle(f);
        assertState(f.txId, TxState.Settled);
        assertEq(pprev.credit(address(actor)), COLLATERAL);
        assertEq(applicant.balance - applicantBefore, DEPOSIT);
        assertEq(address(pprev).balance, COLLATERAL);
    }

    function test_Payout_settle_creditsOwnerThatRefuses() public {
        settleOwnerRefusal(Actor.Mode.Refuse);
    }

    function test_Payout_settle_creditsOwnerThatBurnsGas() public {
        settleOwnerRefusal(Actor.Mode.BurnGas);
    }

    function test_Payout_settle_creditsOwnerWithReturnBomb() public {
        settleOwnerRefusal(Actor.Mode.ReturnBomb);
    }

    // ------------------------------------------------------------------ Settle, counterparty refuses

    function settleCounterpartyRefusal(Actor.Mode mode) internal {
        Flow memory f = actorApplicantEngaged();
        actor.setMode(mode);
        uint256 ownerBefore = owner.balance;
        vm.expectEmit(address(pprev));
        emit PayoutCredited(address(actor), DEPOSIT);
        doSettle(settleCall(f));
        assertState(f.txId, TxState.Settled);
        assertEq(pprev.credit(address(actor)), DEPOSIT);
        assertEq(owner.balance - ownerBefore, COLLATERAL);
    }

    function test_Payout_settle_creditsCounterpartyThatRefuses() public {
        settleCounterpartyRefusal(Actor.Mode.Refuse);
    }

    function test_Payout_settle_creditsCounterpartyThatBurnsGas() public {
        settleCounterpartyRefusal(Actor.Mode.BurnGas);
    }

    function test_Payout_settle_creditsCounterpartyWithReturnBomb() public {
        settleCounterpartyRefusal(Actor.Mode.ReturnBomb);
    }

    // ------------------------------------------------------------------ Expire, counterparty refuses

    function expireCounterpartyRefusal(Actor.Mode mode) internal {
        Flow memory f = actorApplicantEngaged();
        actor.setMode(mode);
        uint256 compensation = COLLATERAL - COLLATERAL * RHO / 10_000;
        lapseAndExpire(f);
        assertState(f.txId, TxState.Expired);
        assertEq(pprev.credit(address(actor)), DEPOSIT + compensation);
    }

    function test_Payout_expire_creditsCounterpartyThatRefuses() public {
        expireCounterpartyRefusal(Actor.Mode.Refuse);
    }

    function test_Payout_expire_creditsCounterpartyThatBurnsGas() public {
        expireCounterpartyRefusal(Actor.Mode.BurnGas);
    }

    function test_Payout_expire_creditsCounterpartyWithReturnBomb() public {
        expireCounterpartyRefusal(Actor.Mode.ReturnBomb);
    }

    // ------------------------------------------------------------------ exhausting Expire, owner refuses

    function exhaustingOwnerRefusal(Actor.Mode mode) internal {
        Flow memory f = actorOwnerEngaged();
        lapseAndExpire(f);
        f.ac = applyCall(f, applicant2);
        f.appId = doApply(f.ac);
        actorEngage(f);
        lapseAndExpire(f);
        f.ac = applyCall(f, applicant);
        f.appId = doApply(f.ac);
        actorEngage(f);
        actor.setMode(mode);
        lapseAndExpire(f);
        assertState(f.txId, TxState.Cancelled);
        assertEq(pprev.credit(address(actor)), COLLATERAL / 8);
        assertEq(address(pprev).balance, COLLATERAL / 8);
    }

    function test_Payout_exhaustingExpire_creditsOwnerThatRefuses() public {
        exhaustingOwnerRefusal(Actor.Mode.Refuse);
    }

    function test_Payout_exhaustingExpire_creditsOwnerThatBurnsGas() public {
        exhaustingOwnerRefusal(Actor.Mode.BurnGas);
    }

    function test_Payout_exhaustingExpire_creditsOwnerWithReturnBomb() public {
        exhaustingOwnerRefusal(Actor.Mode.ReturnBomb);
    }

    // ------------------------------------------------------------------ Reclaim, depositor refuses

    function reclaimRefusal(Actor.Mode mode) internal {
        Flow memory f = actorApplied();
        actor.setMode(mode);
        actorReclaim(f);
        assertEq(pprev.credit(address(actor)), DEPOSIT);
        assertEq(address(pprev).balance, COLLATERAL + DEPOSIT);
    }

    function test_Payout_reclaim_creditsDepositorThatRefuses() public {
        reclaimRefusal(Actor.Mode.Refuse);
    }

    function test_Payout_reclaim_creditsDepositorThatBurnsGas() public {
        reclaimRefusal(Actor.Mode.BurnGas);
    }

    function test_Payout_reclaim_creditsDepositorWithReturnBomb() public {
        reclaimRefusal(Actor.Mode.ReturnBomb);
    }

    // ------------------------------------------------------------------ Cancel, owner refuses

    function cancelRefusal(Actor.Mode mode) internal {
        Flow memory f = actorRegister(RENTAL_R, RENTAL_SHARE);
        actor.setMode(mode);
        actorCancel(f);
        assertState(f.txId, TxState.Cancelled);
        assertEq(pprev.credit(address(actor)), COLLATERAL);
    }

    function test_Payout_cancel_creditsOwnerThatRefuses() public {
        cancelRefusal(Actor.Mode.Refuse);
    }

    function test_Payout_cancel_creditsOwnerThatBurnsGas() public {
        cancelRefusal(Actor.Mode.BurnGas);
    }

    function test_Payout_cancel_creditsOwnerWithReturnBomb() public {
        cancelRefusal(Actor.Mode.ReturnBomb);
    }

    // ------------------------------------------------------------------ re-entry gains nothing

    function test_Payout_reentry_settleOwnerCannotCancel() public {
        Flow memory f = actorOwnerEngaged();
        actor.setMode(Actor.Mode.Reenter);
        actor.setReentry(address(pprev), PPREV.cancel.selector, f.txId);
        uint256 before = address(actor).balance;
        actorSettle(f);
        assertTrue(actor.reentryFailed());
        assertEq(address(actor).balance - before, COLLATERAL);
        assertEq(pprev.credit(address(actor)), 0);
    }

    function test_Payout_reentry_expireCounterpartyCannotExpireAgain() public {
        Flow memory f = actorApplicantEngaged();
        actor.setMode(Actor.Mode.Reenter);
        actor.setReentry(address(pprev), PPREV.expire.selector, f.engId);
        uint256 before = address(actor).balance;
        lapseAndExpire(f);
        assertTrue(actor.reentryFailed());
        assertEq(address(actor).balance - before, DEPOSIT + COLLATERAL - COLLATERAL * RHO / 10_000);
        assertEngStatus(f.engId, EngStatus.Expired);
    }

    function test_Payout_reentry_reclaimCannotReclaimAgain() public {
        Flow memory f = actorApplied();
        actor.setMode(Actor.Mode.Reenter);
        actor.setReentry(address(pprev), PPREV.reclaim.selector, f.appId);
        uint256 before = address(actor).balance;
        actorReclaim(f);
        assertTrue(actor.reentryFailed());
        assertEq(address(actor).balance - before, DEPOSIT);
    }

    function test_Payout_reentry_cancelCannotCancelAgain() public {
        Flow memory f = actorRegister(RENTAL_R, RENTAL_SHARE);
        actor.setMode(Actor.Mode.Reenter);
        actor.setReentry(address(pprev), PPREV.cancel.selector, f.txId);
        uint256 before = address(actor).balance;
        actorCancel(f);
        assertTrue(actor.reentryFailed());
        assertEq(address(actor).balance - before, COLLATERAL);
    }

    // ------------------------------------------------------------------ caller gas

    /// @dev When at least PAYOUT_GAS * 64/63 gas is available at the payout, the recipient receives
    /// exactly PAYOUT_GAS (plus the call stipend) whatever the caller's gas limit, so the caller cannot
    /// turn a payout the recipient accepts into a credit. With less, a failed payout leaves at most
    /// 1/64 of it, too little to record a credit, and the whole call reverts.
    function testFuzz_Payout_callerGasCannotForceCredit(uint256 gasLimit) public {
        Flow memory f = actorApplicantEngaged();
        actor.setMode(Actor.Mode.Accept);
        vm.warp(f.expiresAt + 1);
        gasLimit = bound(gasLimit, 20_000, 400_000);
        uint256 before = address(actor).balance;
        (bool ok,) = address(pprev).call{gas: gasLimit}(abi.encodeCall(PPREV.expire, (f.engId)));
        assertEq(pprev.credit(address(actor)), 0);
        if (ok) {
            assertEq(address(actor).balance - before, DEPOSIT + COLLATERAL - COLLATERAL * RHO / 10_000);
        } else {
            assertEngStatus(f.engId, EngStatus.Open);
            assertEq(address(actor).balance, before);
        }
    }
}
