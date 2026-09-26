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

    /// sigma from the off-chain notary (offchain/crates/pprev-notary/src/sigma.rs) over the register
    /// digest of test-vectors/eip712.json.
    function offchainVector() internal view returns (address vk, bytes32 digest, bytes memory sigma) {
        string memory json = vm.readFile("../test-vectors/notary-signature.json");
        vk = vm.parseJsonAddress(json, ".vkNotary");
        digest = vm.parseJsonBytes32(json, ".digest");
        sigma = vm.parseJsonBytes(json, ".sigma");
        // The key derivation recorded in the vector, and the contract's register digest.
        assertEq(vk, vm.addr(uint256(keccak256("pprev.notary.statement-key.test"))));
        assertEq(digest, vm.parseJsonBytes32(vm.readFile("../test-vectors/eip712.json"), ".register.digest"));
    }

    function test_Verifier_acceptsOffchainNotarySignature() public {
        (address vk, bytes32 digest, bytes memory sigma) = offchainVector();
        assertTrue(new EcdsaNotaryVerifier(vk).verify(digest, sigma));
    }

    function test_Verifier_rejectsAlteredOffchainNotarySignature() public {
        (address vk, bytes32 digest, bytes memory sigma) = offchainVector();
        EcdsaNotaryVerifier offchain = new EcdsaNotaryVerifier(vk);
        sigma[40] ^= 0x01;
        assertFalse(offchain.verify(digest, sigma));
        sigma[40] ^= 0x01;
        assertFalse(offchain.verify(keccak256(abi.encode(digest)), sigma));
        assertFalse(verifier.verify(digest, sigma));
    }
}
