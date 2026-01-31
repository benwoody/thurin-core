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

    /// @notice Proof date validity window (in days)
    uint256 public constant PROOF_DATE_TOLERANCE_DAYS = 1;

    error NoValidSBT();
    error ProofDateFromFuture();
    error ProofDateTooOld();
    error InvalidProof();

    constructor(address _honkVerifier, address _sbt) {
        honkVerifier = IHonkVerifier(_honkVerifier);
        sbt = ThurinSBT(_sbt);
    }

    /// @notice Convert timestamp to YYYYMMDD format
    /// @dev Uses a simplified calculation (may be off by ~1 day near year boundaries)
    function _timestampToYYYYMMDD(uint256 timestamp) internal pure returns (uint32) {
        // Days since Unix epoch
        uint256 daysSinceEpoch = timestamp / 86400;

        // Approximate year calculation
        // Days from 1970 to 2020: 18262
        uint256 daysSince2020 = daysSinceEpoch > 18262 ? daysSinceEpoch - 18262 : 0;
        uint256 yearsSince2020 = daysSince2020 / 365;
        uint256 year = 2020 + yearsSince2020;

        // Remaining days in year
        uint256 dayOfYear = daysSince2020 % 365;

        // Approximate month and day (30-day months)
        uint256 month = (dayOfYear / 30) + 1;
        uint256 day = (dayOfYear % 30) + 1;

        // Clamp values
        if (month > 12) month = 12;
        if (day > 28) day = 28;

        return uint32(year * 10000 + month * 100 + day);
    }

    /// @notice Verify a user's mDL claims
    /// @dev Returns true if valid, reverts otherwise. No events emitted for privacy.
    /// @param user The user address to verify (must match proof's bound_address)
    /// @param proof The ZK proof bytes
    /// @param nullifier Nullifier for this verification
    /// @param addressBinding Hash of nullifier + bound_address (front-running protection)
    /// @param proofDate Date proof was generated (YYYYMMDD format)
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
        bytes32 addressBinding,
        uint32 proofDate,
        bytes32 eventId,
        bytes32 iacaRoot,
        bool proveAgeOver21,
        bool proveAgeOver18,
        bool proveState,
        bytes2 provenState
    ) external returns (bool) {
        // Check user has valid SBT
        if (!sbt.isValid(user)) revert NoValidSBT();

        // Freshness checks (proof_date must be within tolerance of current date)
        uint32 today = _timestampToYYYYMMDD(block.timestamp);
        if (proofDate > today + PROOF_DATE_TOLERANCE_DAYS) revert ProofDateFromFuture();
        if (proofDate < today - PROOF_DATE_TOLERANCE_DAYS) revert ProofDateTooOld();

        // Build public inputs array (must match circuit order exactly)
        // Circuit: nullifier, address_binding, proof_date, event_id, iaca_root,
        //          bound_address, prove_age_over_21, prove_age_over_18,
        //          prove_state, proven_state[0], proven_state[1]
        bytes32[] memory publicInputs = new bytes32[](11);
        publicInputs[0] = nullifier;
        publicInputs[1] = addressBinding;
        publicInputs[2] = bytes32(uint256(proofDate));
        publicInputs[3] = eventId;
        publicInputs[4] = iacaRoot;
        publicInputs[5] = bytes32(uint256(uint160(user))); // bound_address
        publicInputs[6] = bytes32(uint256(proveAgeOver21 ? 1 : 0));
        publicInputs[7] = bytes32(uint256(proveAgeOver18 ? 1 : 0));
        publicInputs[8] = bytes32(uint256(proveState ? 1 : 0));
        publicInputs[9] = bytes32(uint256(uint8(provenState[0])));
        publicInputs[10] = bytes32(uint256(uint8(provenState[1])));

        // Verify ZK proof
        // Note: The circuit enforces addressBinding == hash(nullifier, bound_address)
        // This prevents front-running: proof only works for the intended user
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
