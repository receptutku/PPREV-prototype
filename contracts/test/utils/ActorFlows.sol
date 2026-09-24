// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow, RegisterCall, ApplyCall, SettleCall} from "./Fixture.sol";
import {PPREV} from "../../src/PPREV.sol";
import {Actor} from "../mocks/Actor.sol";

/// @notice Flows in which a contract Actor takes the owner or the counterparty role.
abstract contract ActorFlows is Fixture {
    Actor internal actor;

    function setUp() public virtual override {
        super.setUp();
        actor = new Actor();
        vm.deal(address(actor), 100 ether);
    }

    function actorRegister(bytes32 policyIdR, uint256 share) internal returns (Flow memory f) {
        f.rc = registerCall(policyIdR, share, address(actor));
        RegisterCall memory c = f.rc;
        bytes memory sigma = signR(xROf(c));
        bytes memory call = abi.encodeCall(PPREV.register, (c.cTx, c.txData, c.policyIdR, c.r, sigma, c.eta, c.tAtt));
        f.txId = abi.decode(actor.execute(address(pprev), c.collateral, call), (uint256));
    }

    function actorApply(Flow memory f) internal {
        f.ac = applyCall(f, address(actor));
        ApplyCall memory c = f.ac;
        bytes memory sigma = signA(xAOf(c));
        bytes memory call = abi.encodeCall(PPREV.applyFor, (c.txId, c.txData, c.r, c.cB, sigma, c.eta, c.tAtt));
        f.appId = abi.decode(actor.execute(address(pprev), c.deposit, call), (uint256));
    }

    function actorEngage(Flow memory f) internal {
        bytes memory call = abi.encodeCall(PPREV.engage, (f.txId, f.appId));
        f.engId = abi.decode(actor.execute(address(pprev), 0, call), (uint256));
        f.expiresAt = vm.getBlockTimestamp() + TAU_LOCK;
    }

    function actorSettle(Flow memory f) internal {
        SettleCall memory c = settleCall(f);
        bytes memory sigma = signS(xSOf(c));
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.settle, (c.engId, c.txData, c.r, sigma, c.eta, c.tAtt)));
    }

    function actorCancel(Flow memory f) internal {
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.cancel, (f.txId)));
    }

    function actorReclaim(Flow memory f) internal {
        actor.execute(address(pprev), 0, abi.encodeCall(PPREV.reclaim, (f.appId)));
    }

    /// @dev Actor owns the listing; `applicant` has applied and been engaged.
    function actorOwnerEngaged() internal returns (Flow memory f) {
        f = actorRegister(RENTAL_R, RENTAL_SHARE);
        f.ac = applyCall(f, applicant);
        f.appId = doApply(f.ac);
        actorEngage(f);
    }

    /// @dev `owner` owns the listing; the Actor has applied.
    function actorApplied() internal returns (Flow memory f) {
        f = flowRegistered();
        actorApply(f);
    }

    /// @dev `owner` owns the listing; the Actor has applied and been engaged.
    function actorApplicantEngaged() internal returns (Flow memory f) {
        f = actorApplied();
        doEngage(f);
    }
}
