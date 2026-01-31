// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ThurinVerifier} from "../src/ThurinVerifier.sol";
import {ThurinSBT} from "../src/ThurinSBT.sol";
import {IHonkVerifier} from "../src/interfaces/IHonkVerifier.sol";

contract MockHonkVerifier is IHonkVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return shouldVerify;
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
        bytes32 iacaRoot,
        bool proveAgeOver21,
        bool proveAgeOver18,
        bool proveState,
        bytes2 provenState
    ) external returns (bool) {
        return verifier.verify(
            user, proof, nullifier, addressBinding, proofDate, eventId, iacaRoot,
            proveAgeOver21, proveAgeOver18, proveState, provenState
        );
    }
}

contract ThurinVerifierTest is Test {
    ThurinVerifier public verifier;
    ThurinSBT public sbt;
    MockHonkVerifier public mockHonk;
    MockDapp public dapp;

    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public owner = makeAddr("owner");

    bytes32 public constant IACA_ROOT_CA = keccak256("california-iaca-root");
    bytes32 public constant EVENT_ID = keccak256("acme-age-check");
    bytes32 public constant MOCK_ADDRESS_BINDING = keccak256("mock-address-binding");
    bytes public constant MOCK_PROOF = hex"deadbeef";
    uint256 public constant NO_REFERRER = type(uint256).max;
    uint32 public constant PROOF_DATE_20240101 = 20240101; // Matches vm.warp(1704067200)

    bool public constant PROVE_AGE_21 = true;
    bool public constant PROVE_AGE_18 = true;
    bool public constant PROVE_STATE = true;
    bytes2 public constant STATE_CA = "CA";

    function setUp() public {
        vm.warp(1704067200);

        mockHonk = new MockHonkVerifier();

        vm.prank(owner);
        sbt = new ThurinSBT(address(mockHonk));

        vm.prank(owner);
        sbt.addIACARoot(IACA_ROOT_CA, "California");

        verifier = new ThurinVerifier(address(mockHonk), address(sbt));
        dapp = new MockDapp(address(verifier));

        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    // Helper to mint SBT for user
    function _mintSBT(address user) internal {
        bytes32 nullifier = keccak256(abi.encodePacked("sbt-nullifier", user));
        uint256 price = sbt.getMintPrice();
        vm.prank(user);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101, bytes32(0), IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsVerifier() public view {
        assertEq(address(verifier.honkVerifier()), address(mockHonk));
    }

    function test_constructor_setsSBT() public view {
        assertEq(address(verifier.sbt()), address(sbt));
    }

    /*//////////////////////////////////////////////////////////////
                            VERIFY
    //////////////////////////////////////////////////////////////*/

    function test_verify_succeedsWithValidSBT() public {
        _mintSBT(alice);

        bytes32 nullifier = keccak256("verification-nullifier");

        bool result = dapp.verifyUser(
            alice, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );

        assertTrue(result);
    }

    function test_verify_revertsWithNoSBT() public {
        bytes32 nullifier = keccak256("verification-nullifier");

        vm.expectRevert(ThurinVerifier.NoValidSBT.selector);
        dapp.verifyUser(
            alice, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_verify_revertsWithExpiredSBT() public {
        _mintSBT(alice);

        // Warp past SBT validity period (to 2025)
        vm.warp(block.timestamp + sbt.validityPeriod() + 1);

        bytes32 nullifier = keccak256("verification-nullifier");
        uint32 futureDate = 20250101; // Date matches warped time

        vm.expectRevert(ThurinVerifier.NoValidSBT.selector);
        dapp.verifyUser(
            alice, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, futureDate,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_verify_revertsWithFutureDate() public {
        _mintSBT(alice);

        bytes32 nullifier = keccak256("verification-nullifier");
        uint32 futureDate = 20240105; // 4 days in future (tolerance is 1 day)

        vm.expectRevert(ThurinVerifier.ProofDateFromFuture.selector);
        dapp.verifyUser(
            alice, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, futureDate,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_verify_revertsWithOldDate() public {
        _mintSBT(alice);

        bytes32 nullifier = keccak256("verification-nullifier");
        uint32 oldDate = 20231225; // A week before (tolerance is 1 day)

        vm.expectRevert(ThurinVerifier.ProofDateTooOld.selector);
        dapp.verifyUser(
            alice, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, oldDate,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_verify_revertsWithInvalidProof() public {
        _mintSBT(alice);

        bytes32 nullifier = keccak256("verification-nullifier");
        mockHonk.setShouldVerify(false);

        vm.expectRevert(ThurinVerifier.InvalidProof.selector);
        dapp.verifyUser(
            alice, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    /*//////////////////////////////////////////////////////////////
                            DAPP TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_verify_tracksDappVerifications() public {
        _mintSBT(alice);
        _mintSBT(bob);

        bytes32 nullifier1 = keccak256("nullifier-1");
        bytes32 nullifier2 = keccak256("nullifier-2");

        assertEq(verifier.dappVerificationCount(address(dapp)), 0);

        dapp.verifyUser(
            alice, MOCK_PROOF, nullifier1, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );

        assertEq(verifier.dappVerificationCount(address(dapp)), 1);

        dapp.verifyUser(
            bob, MOCK_PROOF, nullifier2, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            EVENT_ID, IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );

        assertEq(verifier.dappVerificationCount(address(dapp)), 2);
    }

    function test_verify_tracksDifferentDappsSeparately() public {
        _mintSBT(alice);

        MockDapp dapp2 = new MockDapp(address(verifier));

        bytes32 nullifier1 = keccak256("nullifier-1");
        bytes32 nullifier2 = keccak256("nullifier-2");

        dapp.verifyUser(
            alice, MOCK_PROOF, nullifier1, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            keccak256("event-1"), IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );

        dapp2.verifyUser(
            alice, MOCK_PROOF, nullifier2, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            keccak256("event-2"), IACA_ROOT_CA, PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );

        assertEq(verifier.dappVerificationCount(address(dapp)), 1);
        assertEq(verifier.dappVerificationCount(address(dapp2)), 1);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_hasValidSBT_returnsTrue() public {
        _mintSBT(alice);
        assertTrue(verifier.hasValidSBT(alice));
    }

    function test_hasValidSBT_returnsFalseForNoSBT() public view {
        assertFalse(verifier.hasValidSBT(alice));
    }

    function test_hasValidSBT_returnsFalseForExpiredSBT() public {
        _mintSBT(alice);
        vm.warp(block.timestamp + sbt.validityPeriod() + 1);
        assertFalse(verifier.hasValidSBT(alice));
    }

    function test_getSBTExpiry_returnsCorrectTimestamp() public {
        uint256 mintTime = block.timestamp;
        _mintSBT(alice);
        assertEq(verifier.getSBTExpiry(alice), mintTime + sbt.validityPeriod());
    }

    function test_getSBTExpiry_returnsZeroForNoSBT() public view {
        assertEq(verifier.getSBTExpiry(alice), 0);
    }

    /*//////////////////////////////////////////////////////////////
                            SELECTIVE DISCLOSURE
    //////////////////////////////////////////////////////////////*/

    function test_verify_respectsSelectiveDisclosure() public {
        _mintSBT(alice);

        bytes32 nullifier = keccak256("verification-nullifier");

        // Only prove age over 21, not state - proof still verifies
        bool result = dapp.verifyUser(
            alice, MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE_20240101,
            EVENT_ID, IACA_ROOT_CA,
            true,  // prove age 21
            false, // don't prove age 18
            false, // don't prove state
            bytes2(0)
        );

        assertTrue(result);
    }
}
