// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IThurinPoints
/// @notice Interface for Thurin Points contract
/// @dev Use this interface for dApp integrations with the points system
interface IThurinPoints {
    /// @notice Get user points (stored in ThurinSBT)
    /// @param user The user address to check
    /// @return points The user's point balance
    function userPoints(address user) external view returns (uint256 points);

    /// @notice Check if user has valid SBT
    /// @param user The user address to check
    /// @return valid True if user has valid SBT
    function hasValidSBT(address user) external view returns (bool valid);

    /// @notice Get dApp info
    /// @param dapp The dApp address
    /// @return name The dApp name
    /// @return points Total points earned
    /// @return verifications Total verifications performed
    function getDappInfo(address dapp) external view returns (
        string memory name,
        uint256 points,
        uint256 verifications
    );

    /// @notice Get top dApps by verification count
    /// @param limit Max number of dApps to return
    /// @return dapps Array of dApp addresses
    /// @return verifications Array of verification counts
    function getTopDapps(uint256 limit) external view returns (
        address[] memory dapps,
        uint256[] memory verifications
    );

    /// @notice Claim points for verifications performed through ThurinVerifier
    /// @param dapp The dApp address to claim points for
    /// @return claimed The number of points claimed
    function claimDappPoints(address dapp) external returns (uint256 claimed);

    /// @notice Get unclaimed points for a dApp
    /// @param dapp The dApp address to check
    /// @return pending The number of points available to claim
    function pendingDappPoints(address dapp) external view returns (uint256 pending);

    /// @notice Get total dApp points (claimed + pending)
    /// @param dapp The dApp address to check
    /// @return total The total points earned
    function totalDappPoints(address dapp) external view returns (uint256 total);

    /// @notice Register a dApp with a name (optional, for display purposes)
    /// @param name Human-readable name for the dApp
    function registerDapp(string calldata name) external;
}
