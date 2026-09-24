// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {EcdsaNotaryVerifier} from "../src/verifiers/EcdsaNotaryVerifier.sol";

contract EcdsaNotaryVerifierTest is Test {
    uint256 internal constant PK = uint256(keccak256("verifier.test.key"));
    uint256 internal constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    bytes32 internal constant DIGEST = keccak256("message");

    EcdsaNotaryVerifier internal verifier;

    function setUp() public {
        verifier = new EcdsaNotaryVerifier(vm.addr(PK));
    }

    function sign(uint256 pk, bytes32 d) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        (v, r, s) = vm.sign(pk, d);
    }

    function test_Verifier_acceptsNotarySignature() public view {
        (uint8 v, bytes32 r, bytes32 s) = sign(PK, DIGEST);
        assertTrue(verifier.verify(DIGEST, abi.encodePacked(r, s, v)));
    }

    function test_Verifier_rejectsOtherSigner() public view {
        (uint8 v, bytes32 r, bytes32 s) = sign(uint256(keccak256("other")), DIGEST);
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(r, s, v)));
    }

    function test_Verifier_rejectsOtherDigest() public view {
        (uint8 v, bytes32 r, bytes32 s) = sign(PK, DIGEST);
        assertFalse(verifier.verify(keccak256("other message"), abi.encodePacked(r, s, v)));
    }

    function test_Verifier_rejectsWrongLength() public view {
        (uint8 v, bytes32 r, bytes32 s) = sign(PK, DIGEST);
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(r, s)));
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(r, s, v, uint8(0))));
        assertFalse(verifier.verify(DIGEST, ""));
    }

    function test_Verifier_rejectsHighS() public view {
        (uint8 v, bytes32 r, bytes32 s) = sign(PK, DIGEST);
        bytes32 highS = bytes32(CURVE_ORDER - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        // ecrecover alone would accept the malleated signature for the same key.
        assertEq(ecrecover(DIGEST, flippedV, r, highS), vm.addr(PK));
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(r, highS, flippedV)));
    }

    function test_Verifier_rejectsInvalidV() public view {
        (, bytes32 r, bytes32 s) = sign(PK, DIGEST);
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(r, s, uint8(0))));
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(r, s, uint8(1))));
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(r, s, uint8(29))));
    }

    function test_Verifier_rejectsUnrecoverableSignature() public view {
        assertFalse(verifier.verify(DIGEST, abi.encodePacked(bytes32(0), bytes32(0), uint8(27))));
    }

    function test_Verifier_constructorRejectsZeroKey() public {
        vm.expectRevert(EcdsaNotaryVerifier.InvalidKey.selector);
        new EcdsaNotaryVerifier(address(0));
    }
}
