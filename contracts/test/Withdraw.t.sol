// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Flow} from "./utils/Fixture.sol";
import {ActorFlows} from "./utils/ActorFlows.sol";
import {Actor} from "./mocks/Actor.sol";
import {PPREV} from "../src/PPREV.sol";
import {Withdrawn, NothingToWithdraw, WithdrawFailed} from "../src/PPREVTypes.sol";

/// @notice Withdraw (Section V-A): a credited balance stays claimable by its recipient.
contract WithdrawTest is ActorFlows {
    function creditActor() internal returns (Flow memory f) {
        f = actorRegister(RENTAL_R, RENTAL_SHARE);
        actor.setMode(Actor.Mode.Refuse);
        actorCancel(f);
        assertEq(pprev.credit(address(actor)), COLLATERAL);
    }

    function test_Withdraw_paysCreditOnceRecipientAccepts() public {
        creditActor();
        actor.setMode(Actor.Mode.Accept);
        uint256 before = address(actor).balance;
        vm.expectEmit(address(pprev));
        emit Withdrawn(address(actor), COLLATERAL);
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.withdraw, ()));
        assertEq(address(actor).balance - before, COLLATERAL);
        assertEq(pprev.credit(address(actor)), 0);
        assertEq(address(pprev).balance, 0);
    }

    function test_Withdraw_revertsWithoutCredit() public {
        vm.expectRevert(NothingToWithdraw.selector);
        vm.prank(owner);
        pprev.withdraw();
    }

    function test_Withdraw_revertsTwice() public {
        creditActor();
        actor.setMode(Actor.Mode.Accept);
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.withdraw, ()));
        vm.expectRevert(NothingToWithdraw.selector);
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.withdraw, ()));
    }

    function test_Withdraw_revertsAndKeepsCreditWhileRecipientRefuses() public {
        creditActor();
        vm.expectRevert(WithdrawFailed.selector);
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.withdraw, ()));
        assertEq(pprev.credit(address(actor)), COLLATERAL);
    }

    function test_Withdraw_reentryGainsNothing() public {
        creditActor();
        actor.setMode(Actor.Mode.Reenter);
        actor.setReentry(address(pprev), PPREV.withdraw.selector, 0);
        uint256 before = address(actor).balance;
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.withdraw, ()));
        assertTrue(actor.reentryFailed());
        assertEq(address(actor).balance - before, COLLATERAL);
        assertEq(address(pprev).balance, 0);
    }
}
