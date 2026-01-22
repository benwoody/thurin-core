// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IHonkVerifier} from "./interfaces/IHonkVerifier.sol";
import {ThurinSBT} from "./ThurinSBT.sol";

/// @title ThurinVerifier
/// @notice Privacy-preserving verification contract for dApps
/// @dev Verifies ZK proofs and returns only true/false. No events, no data logging.
contract ThurinVerifier {
    IHonkVerifier public immutable honkVerifier;
    ThurinSBT public immutable sbt;

    /// @notice Verification count per dApp (for points)
    mapping(address => uint256) public dappVerificationCount;

    /// @notice Proof validity window
    uint256 public constant PROOF_VALIDITY_PERIOD = 1 hours;

    error NoValidSBT();
    error ProofFromFuture();
    error ProofExpired();
    error InvalidProof();

    constructor(address _honkVerifier, address _sbt) {
        honkVerifier = IHonkVerifier(_honkVerifier);
        sbt = ThurinSBT(_sbt);
    }

    /// @notice Verify a user's mDL claims
    /// @dev Returns true if valid, reverts otherwise. No events emitted for privacy.
    /// @param user The user address to verify (must match proof's bound_address)
    /// @param proof The ZK proof bytes
    /// @param nullifier Nullifier for this verification
    /// @param proofTimestamp When the proof was generated
    /// @param eventId Application-specific event identifier
    /// @param iacaRoot Hash of the IACA public key used
    /// @param proveAgeOver21 Whether age_over_21 claim is proven
    /// @param proveAgeOver18 Whether age_over_18 claim is proven
    /// @param proveState Whether state claim is proven
    /// @param provenState The 2-byte state code (used in proof verification)
    /// @return True if proof is valid
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
    ) external returns (bool) {
        // Check user has valid SBT
        if (!sbt.isValid(user)) revert NoValidSBT();

        // Freshness checks
        if (proofTimestamp > block.timestamp) revert ProofFromFuture();
        if (proofTimestamp < block.timestamp - PROOF_VALIDITY_PERIOD) revert ProofExpired();

        // Build public inputs array (must match circuit order)
        bytes32[] memory publicInputs = new bytes32[](10);
        publicInputs[0] = nullifier;
        publicInputs[1] = bytes32(proofTimestamp);
        publicInputs[2] = eventId;
        publicInputs[3] = iacaRoot;
        publicInputs[4] = bytes32(uint256(uint160(user))); // bound_address
        publicInputs[5] = bytes32(uint256(proveAgeOver21 ? 1 : 0));
        publicInputs[6] = bytes32(uint256(proveAgeOver18 ? 1 : 0));
        publicInputs[7] = bytes32(uint256(proveState ? 1 : 0));
        publicInputs[8] = bytes32(uint256(uint8(provenState[0])));
        publicInputs[9] = bytes32(uint256(uint8(provenState[1])));

        // Verify ZK proof
        if (!honkVerifier.verify(proof, publicInputs)) revert InvalidProof();

        // Track verification for dApp points (no personal data stored)
        dappVerificationCount[msg.sender]++;

        return true;
    }

    /// @notice Simple check if user has valid SBT (no proof required)
    /// @param user The address to check
    /// @return True if user has valid SBT
    function hasValidSBT(address user) external view returns (bool) {
        return sbt.isValid(user);
    }

    /// @notice Get SBT expiry for a user
    /// @param user The address to check
    /// @return Expiry timestamp (0 if no SBT)
    function getSBTExpiry(address user) external view returns (uint256) {
        return sbt.getExpiry(user);
    }
}
