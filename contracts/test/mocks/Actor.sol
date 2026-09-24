// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Contract participant whose reaction to incoming payments is configurable.
contract Actor {
    enum Mode {
        Accept,
        Refuse,
        BurnGas,
        ReturnBomb,
        Reenter
    }

    uint256 internal constant REENTRY_UNSET = 1;
    uint256 internal constant REENTRY_FAILED = 2;
    uint256 internal constant REENTRY_SUCCEEDED = 3;

    Mode public mode;
    address public reentryTarget;
    /// @dev Kept to a single word so that the re-entrant call fits in the payout stipend.
    bytes4 public reentrySelector;
    uint256 public reentryArg;
    /// @dev Starts non-zero so that recording the outcome is a cheap slot update.
    uint256 public reentryResult = REENTRY_UNSET;

    function setMode(Mode m) external {
        mode = m;
    }

    function setReentry(address target, bytes4 selector, uint256 arg) external {
        reentryTarget = target;
        reentrySelector = selector;
        reentryArg = arg;
    }

    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function reentryFailed() external view returns (bool) {
        return reentryResult == REENTRY_FAILED;
    }

    receive() external payable {
        Mode m = mode;
        if (m == Mode.Accept) return;
        if (m == Mode.Refuse) revert("Actor: refused");
        if (m == Mode.ReturnBomb) {
            assembly ("memory-safe") {
                revert(0, 60000)
            }
        }
        if (m == Mode.Reenter) {
            bytes memory data = reentrySelector == bytes4(0) ? bytes("") : abi.encodePacked(reentrySelector, reentryArg);
            (bool ok,) = reentryTarget.call(data);
            reentryResult = ok ? REENTRY_SUCCEEDED : REENTRY_FAILED;
            return;
        }
        // Mode.BurnGas: consume every unit of forwarded gas.
        while (true) {}
    }
}
