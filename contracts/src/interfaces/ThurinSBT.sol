// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import { IThurinSBT, THURIN_SBT } from "./IThurinSBT.sol";

/// @title ThurinSBT
/// @notice Library for easy Thurin SBT verification
/// @dev Wraps IThurinSBT calls with the canonical address
library ThurinSBT {
    /// @notice Check if user has valid (non-expired) SBT
    function isValid(address user) internal view returns (bool) {
        return IThurinSBT(THURIN_SBT).isValid(user);
    }

    /// @notice Get user's SBT expiry timestamp
    function getExpiry(address user) internal view returns (uint256) {
        return IThurinSBT(THURIN_SBT).getExpiry(user);
    }

    /// @notice Get current mint price (tiered based on supply)
    function getMintPrice() internal view returns (uint256) {
        return IThurinSBT(THURIN_SBT).getMintPrice();
    }

    /// @notice Get user's points balance
    function points(address user) internal view returns (uint256) {
        return IThurinSBT(THURIN_SBT).points(user);
    }
}
