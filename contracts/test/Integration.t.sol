// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ThurinSBT} from "../src/ThurinSBT.sol";
import {ThurinVerifier} from "../src/ThurinVerifier.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

/// @notice Integration test using real ZK proof
contract IntegrationTest is Test {
    ThurinSBT public sbt;
    ThurinVerifier public verifier;
    HonkVerifier public honkVerifier;
    MockPriceFeed public mockPriceFeed;

    // Proof fixture values (generated from circuits/ with nargo + bb)
    bytes32 constant NULLIFIER = 0x239b635af19e20630ee162e69a859af142f4b1b4881f39821624b4cdbce4011d;
    bytes32 constant ADDRESS_BINDING = 0x0c44ca206b03e00a11126eb68bf22f767e2c0394ebd58c1aaa1959647558c604;
    uint32 constant PROOF_DATE = 20240101; // YYYYMMDD format
    uint256 constant PROOF_TIMESTAMP = 0x65920080; // 1704067200 = Jan 1, 2024 (for SBT mint)
    bytes32 constant EVENT_ID = bytes32(uint256(1));
    bytes32 constant IACA_ROOT = 0x1a4b0af3464ac266543e11f1c1c7da4d3aa52719ab339bb45f5de7cb73b04b02;
    address constant BOUND_ADDRESS = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;
    bool constant PROVE_AGE_21 = true;
    bool constant PROVE_AGE_18 = true;
    bool constant PROVE_STATE = true;
    bytes2 constant STATE_CA = "CA";
    uint256 constant NO_REFERRER = type(uint256).max;

    function setUp() public {
        // Warp to proof timestamp (proof is valid for 1 hour)
        vm.warp(PROOF_TIMESTAMP);

        // Deploy contracts
        honkVerifier = new HonkVerifier();
        mockPriceFeed = new MockPriceFeed(2000 * 1e8); // $2000/ETH
        sbt = new ThurinSBT(address(honkVerifier), address(mockPriceFeed));
        verifier = new ThurinVerifier(address(honkVerifier), address(sbt));

        // Add trusted IACA root
        sbt.addIACARoot(IACA_ROOT, "California");

        // Fund the bound address
        vm.deal(BOUND_ADDRESS, 10 ether);
    }

    function test_integration_realProofMintsSBT() public {
        // Load proof from fixture (binary file)
        bytes memory proof = vm.readFileBinary("test/fixtures/proof.bin");

        uint256 price = sbt.getMintPrice();

        // Prank as the bound address (proof is bound to this wallet)
        vm.prank(BOUND_ADDRESS);

        uint256 tokenId = sbt.mint{value: price}(
            proof,
            NULLIFIER,
            ADDRESS_BINDING,
            PROOF_DATE,
            EVENT_ID,
            IACA_ROOT,
            PROVE_AGE_21,
            PROVE_AGE_18,
            PROVE_STATE,
            STATE_CA,
            NO_REFERRER
        );

        assertEq(tokenId, 0, "Should mint token 0");
        assertEq(sbt.balanceOf(BOUND_ADDRESS), 1, "Should have 1 SBT");
        assertEq(sbt.ownerOf(0), BOUND_ADDRESS, "Should own token 0");
        assertTrue(sbt.isValid(BOUND_ADDRESS), "Should be valid");
        assertTrue(sbt.nullifierUsed(NULLIFIER), "Nullifier should be used");
    }

    function test_integration_verifierRequiresSBT() public {
        // Load proof from fixture
        bytes memory proof = vm.readFileBinary("test/fixtures/proof.bin");

        // Try to verify without SBT - should fail
        vm.expectRevert(ThurinVerifier.NoValidSBT.selector);
        verifier.verify(
            BOUND_ADDRESS,
            proof,
            NULLIFIER,
            ADDRESS_BINDING,
            PROOF_DATE,
            EVENT_ID,
            IACA_ROOT,
            PROVE_AGE_21,
            PROVE_AGE_18,
            PROVE_STATE,
            STATE_CA
        );
    }

    function test_integration_fullFlow() public {
        // Load proof from fixture
        bytes memory proof = vm.readFileBinary("test/fixtures/proof.bin");

        // Step 1: Mint SBT
        uint256 price = sbt.getMintPrice();
        vm.prank(BOUND_ADDRESS);
        sbt.mint{value: price}(
            proof,
            NULLIFIER,
            ADDRESS_BINDING,
            PROOF_DATE,
            EVENT_ID,
            IACA_ROOT,
            PROVE_AGE_21,
            PROVE_AGE_18,
            PROVE_STATE,
            STATE_CA,
            NO_REFERRER
        );

        assertTrue(sbt.isValid(BOUND_ADDRESS), "Should have valid SBT");

        // Step 2: Verify via ThurinVerifier (simulating dApp call)
        // Note: We'd need a different proof with different nullifier for this
        // For now, just verify the SBT check works
        assertTrue(verifier.hasValidSBT(BOUND_ADDRESS), "Verifier should see valid SBT");
        assertEq(verifier.getSBTExpiry(BOUND_ADDRESS), PROOF_TIMESTAMP + sbt.validityPeriod(), "Expiry should match");
    }
}
