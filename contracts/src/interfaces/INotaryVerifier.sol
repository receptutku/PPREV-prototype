// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Signature check SVer(vk_notary, m, sigma) of Section III-E, on an EIP-712 digest m.
interface INotaryVerifier {
    /// @return True iff `sigma` is a valid notary signature on `digest`.
    function verify(bytes32 digest, bytes calldata sigma) external view returns (bool);
}
