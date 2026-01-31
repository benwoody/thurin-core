// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ThurinSBT} from "./ThurinSBT.sol";
import {ThurinVerifier} from "./ThurinVerifier.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title ThurinPoints
/// @notice Tracks points for users and dApps in the Thurin ecosystem
/// @dev dApps earn points for verifications, claimable based on ThurinVerifier counts
contract ThurinPoints is Ownable2Step {
    ThurinSBT public immutable sbt;
    ThurinVerifier public immutable verifier;

    /// @notice Points per verification for dApps
    uint256 public constant POINTS_PER_VERIFICATION = 10;

    /// @notice dApp points balance
    mapping(address => uint256) public dappPoints;

    /// @notice How many verifications each dApp has already claimed points for
    mapping(address => uint256) public claimedVerifications;

    /// @notice dApp metadata (optional)
    mapping(address => string) public dappName;
    mapping(address => bool) public dappRegistered;

    /// @notice List of registered dApps for enumeration
    address[] public registeredDapps;

    event DappRegistered(address indexed dapp, string name);
    event DappPointsClaimed(address indexed dapp, uint256 points, uint256 totalVerifications);

    error NothingToClaim();
    error AlreadyRegistered();

    constructor(address _sbt, address _verifier) Ownable(msg.sender) {
        sbt = ThurinSBT(_sbt);
        verifier = ThurinVerifier(_verifier);
    }

    /*//////////////////////////////////////////////////////////////
                            DAPP POINTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Claim points for verifications performed through ThurinVerifier
    /// @dev Anyone can trigger claim for any dApp, points go to dApp address
    /// @param dapp The dApp address to claim points for
    /// @return claimed The number of points claimed
    function claimDappPoints(address dapp) external returns (uint256 claimed) {
        uint256 totalVerifications = verifier.dappVerificationCount(dapp);
        uint256 alreadyClaimed = claimedVerifications[dapp];

        if (totalVerifications <= alreadyClaimed) revert NothingToClaim();

        uint256 unclaimed = totalVerifications - alreadyClaimed;
        claimed = unclaimed * POINTS_PER_VERIFICATION;

        dappPoints[dapp] += claimed;
        claimedVerifications[dapp] = totalVerifications;

        emit DappPointsClaimed(dapp, claimed, totalVerifications);

        return claimed;
    }

    /// @notice Get unclaimed points for a dApp
    /// @param dapp The dApp address to check
    /// @return pending The number of points available to claim
    function pendingDappPoints(address dapp) external view returns (uint256 pending) {
        uint256 totalVerifications = verifier.dappVerificationCount(dapp);
        uint256 alreadyClaimed = claimedVerifications[dapp];

        if (totalVerifications <= alreadyClaimed) return 0;

        return (totalVerifications - alreadyClaimed) * POINTS_PER_VERIFICATION;
    }

    /// @notice Get total dApp points (claimed + pending)
    /// @param dapp The dApp address to check
    /// @return total The total points earned
    function totalDappPoints(address dapp) external view returns (uint256 total) {
        uint256 totalVerifications = verifier.dappVerificationCount(dapp);
        return totalVerifications * POINTS_PER_VERIFICATION;
    }

    /*//////////////////////////////////////////////////////////////
                            USER POINTS (READ FROM SBT)
    //////////////////////////////////////////////////////////////*/

    /// @notice Get user points (stored in ThurinSBT)
    /// @param user The user address to check
    /// @return points The user's point balance
    function userPoints(address user) external view returns (uint256 points) {
        return sbt.points(user);
    }

    /// @notice Check if user has valid SBT
    /// @param user The user address to check
    /// @return valid True if user has valid SBT
    function hasValidSBT(address user) external view returns (bool valid) {
        return sbt.isValid(user);
    }

    /*//////////////////////////////////////////////////////////////
                            DAPP REGISTRY (OPTIONAL)
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a dApp with a name (optional, for display purposes)
    /// @param name Human-readable name for the dApp
    function registerDapp(string calldata name) external {
        if (dappRegistered[msg.sender]) revert AlreadyRegistered();

        dappRegistered[msg.sender] = true;
        dappName[msg.sender] = name;
        registeredDapps.push(msg.sender);

        emit DappRegistered(msg.sender, name);
    }

    /// @notice Get number of registered dApps
    /// @return count The number of registered dApps
    function registeredDappCount() external view returns (uint256 count) {
        return registeredDapps.length;
    }

    /// @notice Get dApp info
    /// @param dapp The dApp address
    /// @return name The dApp name
    /// @return points Total points earned
    /// @return verifications Total verifications performed
    function getDappInfo(address dapp) external view returns (
        string memory name,
        uint256 points,
        uint256 verifications
    ) {
        return (
            dappName[dapp],
            dappPoints[dapp],
            verifier.dappVerificationCount(dapp)
        );
    }

    /*//////////////////////////////////////////////////////////////
                            LEADERBOARDS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get top dApps by verification count
    /// @dev Returns registered dApps sorted by verifications (simple impl, gas heavy for large lists)
    /// @param limit Max number of dApps to return (capped at 100)
    /// @return dapps Array of dApp addresses
    /// @return verifications Array of verification counts
    function getTopDapps(uint256 limit) external view returns (
        address[] memory dapps,
        uint256[] memory verifications
    ) {
        uint256 count = registeredDapps.length;
        if (limit > 100) limit = 100; // Cap to prevent DoS
        if (limit > count) limit = count;

        dapps = new address[](limit);
        verifications = new uint256[](limit);

        // Simple O(n*limit) approach - fine for small lists
        bool[] memory used = new bool[](count);

        for (uint256 i = 0; i < limit; i++) {
            uint256 maxIdx = 0;
            uint256 maxVal = 0;

            for (uint256 j = 0; j < count; j++) {
                if (!used[j]) {
                    uint256 val = verifier.dappVerificationCount(registeredDapps[j]);
                    if (val > maxVal) {
                        maxVal = val;
                        maxIdx = j;
                    }
                }
            }

            used[maxIdx] = true;
            dapps[i] = registeredDapps[maxIdx];
            verifications[i] = maxVal;
        }

        return (dapps, verifications);
    }

}
