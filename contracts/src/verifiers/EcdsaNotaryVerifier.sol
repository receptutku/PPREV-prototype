// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {INotaryVerifier} from "../interfaces/INotaryVerifier.sol";

/// @notice secp256k1 ECDSA verifier for notary signatures. vk_notary is held as the Ethereum
/// address of the notary's statement key.
contract EcdsaNotaryVerifier is INotaryVerifier {
    /// @dev secp256k1n / 2. Signatures with a larger s are rejected, so each message has one valid
    /// signature encoding (EIP-2).
    uint256 private constant HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable VK_NOTARY;

    error InvalidKey();

    constructor(address vkNotary) {
        if (vkNotary == address(0)) revert InvalidKey();
        VK_NOTARY = vkNotary;
    }

    /// @param sigma 65 bytes: r (32) || s (32) || v (1), with v in {27, 28}.
    function verify(bytes32 digest, bytes calldata sigma) external view returns (bool) {
        if (sigma.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(sigma.offset)
            s := calldataload(add(sigma.offset, 32))
            v := byte(0, calldataload(add(sigma.offset, 64)))
        }
        if (uint256(s) > HALF_CURVE_ORDER) return false;
        if (v != 27 && v != 28) return false;
        address signer = ecrecover(digest, v, r, s);
        return signer != address(0) && signer == VK_NOTARY;
    }
}
