// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Fixture, RegisterCall} from "./utils/Fixture.sol";
import {XR} from "./utils/NotarySigner.sol";
import {
    TxState,
    Listing,
    Registered,
    UnknownPolicy,
    CommitmentMismatch,
    InvalidNotarySignature,
    NonceConsumed,
    AttestationFromFuture,
    AttestationExpired,
    CommitmentRegistered,
    CollateralOutOfBounds,
    SettlementShareTooHigh
} from "../src/PPREVTypes.sol";

/// @notice Acceptance conditions R(a)-R(h) of Section V-D.
contract RegisterTest is Fixture {
    function test_Register_storesListingAndEmitsTxData() public {
        RegisterCall memory c = registerCall();
        bytes memory sigma = signR(xROf(c));
        vm.expectEmit(address(pprev));
        emit Registered(1, owner, c.cTx, RENTAL_R, c.txData, c.r, COLLATERAL);
        uint256 txId = submitRegister(c, sigma);

        assertEq(txId, 1);
        Listing memory l = listingOf(txId);
        assertEq(l.cTx, c.cTx);
        assertEq(l.policyIdR, RENTAL_R);
        assertEq(l.owner, owner);
        assertEq(l.collateral, COLLATERAL);
        assertEq(l.expirations, 0);
        assertState(txId, TxState.Active);
        assertTrue(pprev.registered(c.cTx));
        assertTrue(pprev.consumed(c.eta));
        assertEq(address(pprev).balance, COLLATERAL);
        assertEq(pprev.nextTxId(), 2);
    }

    // R(a) -------------------------------------------------------------------------------------

    function test_R_a_acceptsRegisteredPolicies() public {
        assertEq(doRegister(registerCall(RENTAL_R, RENTAL_SHARE, owner)), 1);
        assertEq(doRegister(registerCall(SALE_R, SALE_SHARE, owner)), 2);
    }

    function test_R_a_revertsForUnknownPolicy() public {
        bytes32 unknown = keccak256("unknown policy");
        RegisterCall memory c = registerCall(unknown, RENTAL_SHARE, owner);
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(abi.encodeWithSelector(UnknownPolicy.selector, unknown));
        submitRegister(c, sigma);
    }

    // R(b) -------------------------------------------------------------------------------------

    function test_R_b_acceptsMatchingCommitment() public {
        RegisterCall memory c = registerCall();
        assertEq(
            c.cTx,
            keccak256(
                abi.encodePacked(c.txData.propertyId, c.txData.amount, c.txData.settlementShare, c.policyIdR, c.r)
            )
        );
        doRegister(c);
    }

    function test_R_b_revertsWhenTxDataAltered() public {
        RegisterCall memory c = registerCall();
        c.txData.amount += 1;
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitRegister(c, sigma);
    }

    function test_R_b_revertsWhenPolicyIdAltered() public {
        // Commitment computed for the rental policy, submitted under the (registered) sale policy.
        RegisterCall memory c = registerCall();
        c.policyIdR = SALE_R;
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitRegister(c, sigma);
    }

    function test_R_b_revertsWhenSaltAltered() public {
        RegisterCall memory c = registerCall();
        c.r = next("other salt");
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitRegister(c, sigma);
    }

    function test_R_b_revertsWhenCommitmentAltered() public {
        RegisterCall memory c = registerCall();
        c.cTx = next("other commitment");
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(CommitmentMismatch.selector);
        submitRegister(c, sigma);
    }

    // R(c) -------------------------------------------------------------------------------------

    function test_R_c_acceptsNotarySignature() public {
        RegisterCall memory c = registerCall();
        assertEq(submitRegister(c, signR(xROf(c))), 1);
    }

    function test_R_c_revertsForWrongSigner() public {
        RegisterCall memory c = registerCall();
        bytes memory sigma = signDigest(ROGUE_PK, digest(structHashR(xROf(c))));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, sigma);
    }

    function test_R_c_revertsForOtherSubmitter() public {
        // a_P is fixed to the caller: a payload signed for the owner fails from another address.
        RegisterCall memory c = registerCall();
        bytes memory sigma = signR(xROf(c));
        c.caller = attacker;
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, sigma);
    }

    function test_R_c_revertsForOtherPhaseTag() public {
        RegisterCall memory c = registerCall();
        bytes memory sigma = signUnderTypehash(typehashA(), encodeDataR(xROf(c)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, sigma);
    }

    function test_R_c_revertsForOtherChain() public {
        RegisterCall memory c = registerCall();
        bytes memory sigma = signDigest(NOTARY_PK, digestFor(structHashR(xROf(c)), vm.getChainId() + 1, address(pprev)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, sigma);
    }

    function test_R_c_revertsForOtherDeployment() public {
        RegisterCall memory c = registerCall();
        bytes memory sigma = signDigest(NOTARY_PK, digestFor(structHashR(xROf(c)), vm.getChainId(), address(0xBEEF)));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, sigma);
    }

    function test_R_c_revertsWhenSignedTimestampDiffers() public {
        RegisterCall memory c = registerCall();
        XR memory x = xROf(c);
        x.tAtt -= 1;
        bytes memory sigma = signR(x);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, sigma);
    }

    function test_R_c_revertsWhenSignedNonceDiffers() public {
        RegisterCall memory c = registerCall();
        XR memory x = xROf(c);
        x.eta = next("other eta");
        bytes memory sigma = signR(x);
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, sigma);
    }

    function test_R_c_revertsForMalformedSignature() public {
        RegisterCall memory c = registerCall();
        bytes memory sigma = signR(xROf(c));
        bytes memory truncated = new bytes(64);
        for (uint256 i; i < 64; ++i) {
            truncated[i] = sigma[i];
        }
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, truncated);
    }

    function test_R_c_revertsForHighS() public {
        RegisterCall memory c = registerCall();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NOTARY_PK, digest(structHashR(xROf(c))));
        uint256 n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
        bytes memory malleated = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(InvalidNotarySignature.selector);
        submitRegister(c, malleated);
    }

    // R(d) -------------------------------------------------------------------------------------

    function test_R_d_acceptsFreshNonce() public {
        RegisterCall memory c = registerCall();
        assertFalse(pprev.consumed(c.eta));
        doRegister(c);
        assertTrue(pprev.consumed(c.eta));
    }

    function test_R_d_revertsForConsumedNonce() public {
        RegisterCall memory first = registerCall();
        doRegister(first);
        RegisterCall memory second = registerCall();
        second.eta = first.eta;
        bytes memory sigma = signR(xROf(second));
        vm.expectRevert(abi.encodeWithSelector(NonceConsumed.selector, first.eta));
        submitRegister(second, sigma);
    }

    // R(e) -------------------------------------------------------------------------------------

    function test_R_e_acceptsAtAttestationTime() public {
        RegisterCall memory c = registerCall();
        c.tAtt = now64();
        doRegister(c);
    }

    function test_R_e_acceptsAtWindowEnd() public {
        RegisterCall memory c = registerCall();
        c.tAtt = uint64(vm.getBlockTimestamp() - DELTA);
        doRegister(c);
    }

    function test_R_e_revertsAfterWindow() public {
        RegisterCall memory c = registerCall();
        c.tAtt = uint64(vm.getBlockTimestamp() - DELTA - 1);
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(abi.encodeWithSelector(AttestationExpired.selector, c.tAtt));
        submitRegister(c, sigma);
    }

    function test_R_e_revertsForFutureAttestation() public {
        RegisterCall memory c = registerCall();
        c.tAtt = uint64(vm.getBlockTimestamp() + 1);
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(abi.encodeWithSelector(AttestationFromFuture.selector, c.tAtt));
        submitRegister(c, sigma);
    }

    // R(f) -------------------------------------------------------------------------------------

    function test_R_f_acceptsNewCommitment() public {
        RegisterCall memory c = registerCall();
        assertFalse(pprev.registered(c.cTx));
        doRegister(c);
        assertTrue(pprev.registered(c.cTx));
    }

    function test_R_f_revertsForRegisteredCommitment() public {
        RegisterCall memory first = registerCall();
        doRegister(first);
        RegisterCall memory again = first;
        again.eta = next("fresh eta");
        bytes memory sigma = signR(xROf(again));
        vm.expectRevert(abi.encodeWithSelector(CommitmentRegistered.selector, first.cTx));
        submitRegister(again, sigma);
    }

    function test_R_f_revertsForCommitmentOfCancelledListing() public {
        RegisterCall memory first = registerCall();
        uint256 txId = doRegister(first);
        vm.prank(owner);
        pprev.cancel(txId);
        RegisterCall memory again = first;
        again.eta = next("fresh eta");
        bytes memory sigma = signR(xROf(again));
        vm.expectRevert(abi.encodeWithSelector(CommitmentRegistered.selector, first.cTx));
        submitRegister(again, sigma);
    }

    // R(g) -------------------------------------------------------------------------------------

    function test_R_g_acceptsMinCollateral() public {
        RegisterCall memory c = registerCall();
        c.collateral = MIN_COLLATERAL;
        doRegister(c);
    }

    function test_R_g_acceptsMaxCollateral() public {
        RegisterCall memory c = registerCall();
        c.collateral = MAX_COLLATERAL;
        doRegister(c);
    }

    function test_R_g_revertsBelowMinCollateral() public {
        RegisterCall memory c = registerCall();
        c.collateral = MIN_COLLATERAL - 1;
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(abi.encodeWithSelector(CollateralOutOfBounds.selector, c.collateral));
        submitRegister(c, sigma);
    }

    function test_R_g_revertsAboveMaxCollateral() public {
        RegisterCall memory c = registerCall();
        c.collateral = MAX_COLLATERAL + 1;
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(abi.encodeWithSelector(CollateralOutOfBounds.selector, c.collateral));
        submitRegister(c, sigma);
    }

    // R(h) -------------------------------------------------------------------------------------

    function test_R_h_acceptsFullShare() public {
        doRegister(registerCall(SALE_R, 10_000, owner));
    }

    function test_R_h_revertsAboveFullShare() public {
        RegisterCall memory c = registerCall(SALE_R, 10_001, owner);
        bytes memory sigma = signR(xROf(c));
        vm.expectRevert(abi.encodeWithSelector(SettlementShareTooHigh.selector, 10_001));
        submitRegister(c, sigma);
    }
}
