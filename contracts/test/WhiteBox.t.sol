// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, Flow, ApplyCall} from "./utils/Fixture.sol";
import {PPREVHarness} from "./utils/PPREVHarness.sol";
import {PPREV} from "../src/PPREV.sol";
import {INotaryVerifier} from "../src/interfaces/INotaryVerifier.sol";
import {TxState, NotLocked, ListingNotOpen} from "../src/PPREVTypes.sol";

/// @notice Negative cases of checks that no sequence of external calls can violate while the
/// preceding checks hold. The states are forced through PPREVHarness; the invariant suite shows they
/// are unreachable otherwise.
contract WhiteBoxTest is Fixture {
    PPREVHarness internal harness;

    function deploy(INotaryVerifier v) internal override returns (PPREV) {
        harness = new PPREVHarness(operator, v, DELTA, TAU_LOCK, MAX_EXPIRATIONS, RHO);
        return harness;
    }

    /// @dev An open engagement always belongs to a LOCKED listing, so E(a) implies E(b) in every
    /// reachable state.
    function test_E_b_revertsWhenListingNotLocked() public {
        Flow memory f = flowEngaged();
        harness.forceTxState(f.txId, TxState.Active);
        vm.warp(f.expiresAt + 1);
        vm.expectRevert(abi.encodeWithSelector(NotLocked.selector, f.txId));
        pprev.expire(f.engId);
    }

    /// @dev The exhausting expiration sets CANCELLED, so an EXPIRED listing always has fewer than
    /// maxExpirations expirations; the counter part of "open to applications" is otherwise implied.
    function test_A_a_revertsWhenExpirationCounterReachedMax() public {
        Flow memory f = flowEngaged();
        lapseAndExpire(f);
        harness.forceExpirations(f.txId, MAX_EXPIRATIONS);
        ApplyCall memory c = applyCall(f, applicant2);
        bytes memory sigma = signA(xAOf(c));
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        submitApply(c, sigma);
    }

    function test_Engage_iii_revertsWhenExpirationCounterReachedMax() public {
        Flow memory f = flowApplied();
        uint256 pending = doApply(applyCall(f, applicant2));
        doEngage(f);
        lapseAndExpire(f);
        harness.forceExpirations(f.txId, MAX_EXPIRATIONS);
        vm.expectRevert(abi.encodeWithSelector(ListingNotOpen.selector, f.txId));
        vm.prank(owner);
        pprev.engage(f.txId, pending);
    }
}
