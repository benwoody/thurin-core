// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IThurinVerifier
/// @notice Interface for Thurin Verifier contract
/// @dev Use this interface for dApp integrations requiring ZK proof verification
interface IThurinVerifier {
    /// @notice Check if user has valid SBT
    /// @param user The address to check
    /// @return True if user has valid SBT
    function hasValidSBT(address user) external view returns (bool);

    /// @notice Get the SBT expiry timestamp for a user
    /// @param user The address to check
    /// @return Expiry timestamp (0 if no SBT)
    function getSBTExpiry(address user) external view returns (uint256);

    /// @notice Get the verification count for a dApp
    /// @param dapp The dApp address
    /// @return Number of verifications performed by this dApp
    function dappVerificationCount(address dapp) external view returns (uint256);

    /// @notice Verify a ZK proof for specific claims
    /// @dev Increments dApp verification count. Reverts if invalid.
    /// @param user The user address to verify (must match proof's bound_address)
    /// @param proof The ZK proof bytes
    /// @param nullifier Nullifier for this verification
    /// @param proofTimestamp When the proof was generated
    /// @param eventId Application-specific event identifier
    /// @param iacaRoot Hash of the IACA public key used
    /// @param proveAgeOver21 Whether age_over_21 claim is proven
    /// @param proveAgeOver18 Whether age_over_18 claim is proven
    /// @param proveState Whether state claim is proven
    /// @param provenState The 2-byte state code
    /// @return True if proof is valid (reverts otherwise)
    function verify(
        address user,
        bytes calldata proof,
        bytes32 nullifier,
        uint256 proofTimestamp,
        bytes32 eventId,
        bytes32 iacaRoot,
        bool proveAgeOver21,
        bool proveAgeOver18,
        bool proveState,
        bytes2 provenState
    ) external returns (bool);
}
