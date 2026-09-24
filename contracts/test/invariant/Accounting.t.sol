// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {PPREV} from "../../src/PPREV.sol";
import {INotaryVerifier} from "../../src/interfaces/INotaryVerifier.sol";
import {EcdsaNotaryVerifier} from "../../src/verifiers/EcdsaNotaryVerifier.sol";
import {NotarySigner} from "../utils/NotarySigner.sol";
import {Handler} from "./Handler.sol";

/// @notice State and accounting invariants over random operation sequences (fixture parameters of
/// Section 2.9 of the plan: Delta 300 s, tau_lock 14 days, maxExpirations 3, rho 5000 bp).
contract AccountingInvariantTest is Test, NotarySigner {
    PPREV internal pprev;
    Handler internal handler;

    function setUp() public {
        vm.warp(1_760_000_000);
        address operator = makeAddr("operator");
        EcdsaNotaryVerifier v = new EcdsaNotaryVerifier(vm.addr(NOTARY_PK));
        pprev = new PPREV(operator, INotaryVerifier(address(v)), 300, 14 days, 3, 5000);
        bytes32[6] memory policies = [
            keccak256("pprev.rental.register"),
            keccak256("pprev.rental.apply"),
            keccak256("pprev.rental.settle"),
            keccak256("pprev.sale.register"),
            keccak256("pprev.sale.apply"),
            keccak256("pprev.sale.settle")
        ];
        vm.startPrank(operator);
        pprev.registerPolicy(policies[0], policies[1], policies[2], 0.05 ether, 0.1 ether, 1 ether);
        pprev.registerPolicy(policies[3], policies[4], policies[5], 0.05 ether, 0.1 ether, 1 ether);
        vm.stopPrank();

        handler = new Handler(pprev, policies);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](9);
        selectors[0] = Handler.register.selector;
        selectors[1] = Handler.applyTo.selector;
        selectors[2] = Handler.engage.selector;
        selectors[3] = Handler.settle.selector;
        selectors[4] = Handler.expire.selector;
        selectors[5] = Handler.reclaim.selector;
        selectors[6] = Handler.cancel.selector;
        selectors[7] = Handler.withdraw.selector;
        selectors[8] = Handler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice The contract holds exactly what it owes.
    function invariant_balanceEqualsObligations() public view {
        assertEq(address(pprev).balance, handler.obligations());
    }

    /// @notice Every open engagement's listing is LOCKED, so E(a) implies E(b).
    function invariant_openEngagementListingIsLocked() public view {
        assertEq(handler.openEngagementsNotLocked(), 0);
    }

    /// @notice A listing never has more than one open engagement, so an open engagement is always the
    /// one in progress for its listing.
    function invariant_atMostOneOpenEngagementPerListing() public view {
        assertLe(handler.maxOpenEngagementsPerListing(), 1);
    }

    /// @notice Terminal listings hold no collateral; EXPIRED listings are below maxExpirations.
    function invariant_listingRecordsMatchState() public view {
        assertEq(handler.inconsistentListings(), 0);
    }

    /// @notice After closing every position through the protocol's exits, nothing is left: no terminal
    /// path strands funds.
    function afterInvariant() public {
        handler.drain();
        assertEq(address(pprev).balance, 0);
    }
}
