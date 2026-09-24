// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PPREV} from "../../src/PPREV.sol";
import {Listing} from "../../src/PPREVTypes.sol";

/// @notice Reads a listing record through the generated getter, decoding only the fields the
/// protocol defines (C_tx, policyID_R, owner, collateral, expirations). Tests never read
/// implementation-only fields.
library Records {
    function listing(PPREV pprev, uint256 txId) internal view returns (Listing memory l) {
        (bool ok, bytes memory ret) = address(pprev).staticcall(abi.encodeWithSelector(pprev.listings.selector, txId));
        require(ok, "listings() failed");
        (l.cTx, l.policyIdR, l.owner, l.collateral, l.expirations) =
            abi.decode(ret, (bytes32, bytes32, address, uint256, uint256));
    }
}
