// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IHonkVerifier
/// @notice Interface for the auto-generated Honk verifier contract
interface IHonkVerifier {
    /// @notice Verify a ZK proof
    /// @param proof The proof bytes
    /// @param publicInputs Array of public inputs
    /// @return True if the proof is valid
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external returns (bool);
}
