// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ThurinPoints} from "../src/ThurinPoints.sol";
import {ThurinSBT} from "../src/ThurinSBT.sol";
import {ThurinVerifier} from "../src/ThurinVerifier.sol";
import {IHonkVerifier} from "../src/interfaces/IHonkVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract MockHonkVerifier is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract MockDapp {
    ThurinVerifier public verifier;

    constructor(address _verifier) {
        verifier = ThurinVerifier(_verifier);
    }

    function verifyUser(
        address user,
        bytes calldata proof,
        bytes32 nullifier,
        bytes32 addressBinding,
        uint32 proofDate,
        bytes32 eventId,
        bytes32 iacaRoot
    ) external returns (bool) {
        return verifier.verify(
            user, proof, nullifier, addressBinding, proofDate, eventId, iacaRoot,
            true, true, true, "CA"
        );
    }
}

contract ThurinPointsTest is Test {
    ThurinPoints public points;
    ThurinSBT public sbt;
    ThurinVerifier public verifier;
    MockHonkVerifier public mockHonk;
    MockDapp public dapp1;
    MockDapp public dapp2;

    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public owner = makeAddr("owner");

    bytes32 public constant IACA_ROOT = keccak256("california-iaca-root");
    bytes32 public constant MOCK_ADDRESS_BINDING = keccak256("mock-address-binding");
    bytes public constant MOCK_PROOF = hex"deadbeef";
    uint256 public constant NO_REFERRER = type(uint256).max;
    uint32 public constant PROOF_DATE = 20240101;

    event DappRegistered(address indexed dapp, string name);
    event DappPointsClaimed(address indexed dapp, uint256 points, uint256 totalVerifications);

    function setUp() public {
        vm.warp(1704067200);

        mockHonk = new MockHonkVerifier();

        vm.prank(owner);
        sbt = new ThurinSBT(address(mockHonk));

        vm.prank(owner);
        sbt.addIACARoot(IACA_ROOT, "California");

        verifier = new ThurinVerifier(address(mockHonk), address(sbt));
        points = new ThurinPoints(address(sbt), address(verifier));

        dapp1 = new MockDapp(address(verifier));
        dapp2 = new MockDapp(address(verifier));

        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function _mintSBT(address user, bytes32 nullifier) internal {
        uint256 price = sbt.getMintPrice();
        vm.prank(user);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, bytes32(0), IACA_ROOT,
            true, true, true, "CA", NO_REFERRER
        );
    }

    function _verifyVia(MockDapp dapp, address user, bytes32 nullifier) internal {
        dapp.verifyUser(user, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, keccak256(abi.encode(nullifier)), IACA_ROOT);
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsSBT() public view {
        assertEq(address(points.sbt()), address(sbt));
    }

    function test_constructor_setsVerifier() public view {
        assertEq(address(points.verifier()), address(verifier));
    }

    /*//////////////////////////////////////////////////////////////
                            DAPP POINTS
    //////////////////////////////////////////////////////////////*/

    function test_claimDappPoints_claimsCorrectAmount() public {
        _mintSBT(alice, keccak256("alice-sbt"));
        _mintSBT(bob, keccak256("bob-sbt"));

        // dapp1 verifies 2 users
        _verifyVia(dapp1, alice, keccak256("v1"));
        _verifyVia(dapp1, bob, keccak256("v2"));

        assertEq(verifier.dappVerificationCount(address(dapp1)), 2);

        // Claim points
        vm.expectEmit(true, false, false, true);
        emit DappPointsClaimed(address(dapp1), 20, 2); // 2 * 10 points

        uint256 claimed = points.claimDappPoints(address(dapp1));

        assertEq(claimed, 20);
        assertEq(points.dappPoints(address(dapp1)), 20);
        assertEq(points.claimedVerifications(address(dapp1)), 2);
    }

    function test_claimDappPoints_revertsIfNothingToClaim() public {
        vm.expectRevert(ThurinPoints.NothingToClaim.selector);
        points.claimDappPoints(address(dapp1));
    }

    function test_claimDappPoints_canClaimIncrementally() public {
        _mintSBT(alice, keccak256("alice-sbt"));
        _mintSBT(bob, keccak256("bob-sbt"));

        // First verification
        _verifyVia(dapp1, alice, keccak256("v1"));
        points.claimDappPoints(address(dapp1));
        assertEq(points.dappPoints(address(dapp1)), 10);

        // Second verification
        _verifyVia(dapp1, bob, keccak256("v2"));
        uint256 claimed = points.claimDappPoints(address(dapp1));

        assertEq(claimed, 10); // Only the new one
        assertEq(points.dappPoints(address(dapp1)), 20); // Total
    }

    function test_pendingDappPoints_returnsCorrectAmount() public {
        _mintSBT(alice, keccak256("alice-sbt"));

        assertEq(points.pendingDappPoints(address(dapp1)), 0);

        _verifyVia(dapp1, alice, keccak256("v1"));
        assertEq(points.pendingDappPoints(address(dapp1)), 10);

        points.claimDappPoints(address(dapp1));
        assertEq(points.pendingDappPoints(address(dapp1)), 0);
    }

    function test_totalDappPoints_returnsCorrectAmount() public {
        _mintSBT(alice, keccak256("alice-sbt"));
        _mintSBT(bob, keccak256("bob-sbt"));

        _verifyVia(dapp1, alice, keccak256("v1"));
        _verifyVia(dapp1, bob, keccak256("v2"));

        // Total includes unclaimed
        assertEq(points.totalDappPoints(address(dapp1)), 20);

        // Claim half
        points.claimDappPoints(address(dapp1));

        // Total unchanged
        assertEq(points.totalDappPoints(address(dapp1)), 20);
    }

    /*//////////////////////////////////////////////////////////////
                            USER POINTS (FROM SBT)
    //////////////////////////////////////////////////////////////*/

    function test_userPoints_readsFromSBT() public {
        _mintSBT(alice, keccak256("alice-sbt"));

        // User gets MINT_POINTS (100) from SBT
        assertEq(points.userPoints(alice), sbt.MINT_POINTS());
    }

    function test_hasValidSBT_checksCorrectly() public {
        assertFalse(points.hasValidSBT(alice));

        _mintSBT(alice, keccak256("alice-sbt"));
        assertTrue(points.hasValidSBT(alice));

        // Expire SBT
        vm.warp(block.timestamp + sbt.validityPeriod() + 1);
        assertFalse(points.hasValidSBT(alice));
    }

    /*//////////////////////////////////////////////////////////////
                            DAPP REGISTRY
    //////////////////////////////////////////////////////////////*/

    function test_registerDapp_storesInfo() public {
        vm.prank(address(dapp1));
        vm.expectEmit(true, false, false, true);
        emit DappRegistered(address(dapp1), "Acme App");
        points.registerDapp("Acme App");

        assertTrue(points.dappRegistered(address(dapp1)));
        assertEq(points.dappName(address(dapp1)), "Acme App");
        assertEq(points.registeredDappCount(), 1);
    }

    function test_registerDapp_revertsIfAlreadyRegistered() public {
        vm.prank(address(dapp1));
        points.registerDapp("Acme App");

        vm.prank(address(dapp1));
        vm.expectRevert(ThurinPoints.AlreadyRegistered.selector);
        points.registerDapp("Acme App v2");
    }

    function test_getDappInfo_returnsCorrectData() public {
        vm.prank(address(dapp1));
        points.registerDapp("Acme App");

        _mintSBT(alice, keccak256("alice-sbt"));
        _verifyVia(dapp1, alice, keccak256("v1"));
        points.claimDappPoints(address(dapp1));

        (string memory name, uint256 pts, uint256 vCount) = points.getDappInfo(address(dapp1));

        assertEq(name, "Acme App");
        assertEq(pts, 10);
        assertEq(vCount, 1);
    }

    /*//////////////////////////////////////////////////////////////
                            LEADERBOARD
    //////////////////////////////////////////////////////////////*/

    function test_getTopDapps_returnsOrdered() public {
        // Register dapps
        vm.prank(address(dapp1));
        points.registerDapp("Dapp 1");
        vm.prank(address(dapp2));
        points.registerDapp("Dapp 2");

        _mintSBT(alice, keccak256("alice-sbt"));
        _mintSBT(bob, keccak256("bob-sbt"));

        // dapp1: 1 verification, dapp2: 2 verifications
        _verifyVia(dapp1, alice, keccak256("v1"));
        _verifyVia(dapp2, alice, keccak256("v2"));
        _verifyVia(dapp2, bob, keccak256("v3"));

        (address[] memory dapps, uint256[] memory counts) = points.getTopDapps(2);

        assertEq(dapps[0], address(dapp2)); // dapp2 has more
        assertEq(counts[0], 2);
        assertEq(dapps[1], address(dapp1));
        assertEq(counts[1], 1);
    }

    function test_getTopDapps_handlesLimitLargerThanCount() public {
        vm.prank(address(dapp1));
        points.registerDapp("Dapp 1");

        (address[] memory dapps,) = points.getTopDapps(10);

        assertEq(dapps.length, 1);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_transferOwnership_works() public {
        address newOwner = makeAddr("newOwner");

        // Step 1: Initiate transfer
        points.transferOwnership(newOwner);
        assertEq(points.owner(), address(this)); // Still original owner
        assertEq(points.pendingOwner(), newOwner);

        // Step 2: New owner accepts
        vm.prank(newOwner);
        points.acceptOwnership();
        assertEq(points.owner(), newOwner);
    }

    function test_transferOwnership_revertsIfNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        points.transferOwnership(alice);
    }
}
