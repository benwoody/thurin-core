// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

// Thurin SBT address (same on all chains via CREATE2)
address constant THURIN_SBT = address(0); // TODO: Set after deployment

/// @title IThurinSBT
/// @notice Interface for Thurin Soulbound Token contract
/// @dev Use this interface for dApp integrations
interface IThurinSBT {
    /// @notice Check if user has valid (non-expired) SBT
    /// @param user The address to check
    /// @return True if user has valid SBT
    function isValid(address user) external view returns (bool);

    /// @notice Get user's SBT expiry timestamp
    /// @param user The address to check
    /// @return Expiry timestamp (0 if no SBT)
    function getExpiry(address user) external view returns (uint256);

    /// @notice Get current mint price (tiered based on supply)
    /// @return Price in wei
    function getMintPrice() external view returns (uint256);

    /// @notice Get user's points balance
    /// @param user The address to check
    /// @return Points balance
    function points(address user) external view returns (uint256);
}
