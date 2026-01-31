// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {ThurinSBT} from "../src/ThurinSBT.sol";
import {ThurinVerifier} from "../src/ThurinVerifier.sol";
import {ThurinPoints} from "../src/ThurinPoints.sol";
import {MockPriceFeed} from "../test/mocks/MockPriceFeed.sol";

/// @notice Deploy + mint + verify in one script to demo full flow on Anvil
contract MintTestScript is Script {
    // Proof fixture values (from packages/circuits/)
    bytes32 constant NULLIFIER = 0x1ca63d2c7aa6f7fd4b51b6e0fad8d2c4aa37f5ed994521ada76c1d39fdee89df;
    bytes32 constant ADDRESS_BINDING = 0x0; // TODO: Regenerate with new circuit
    uint32 constant PROOF_DATE = 20240101; // YYYYMMDD format
    bytes32 constant EVENT_ID = bytes32(uint256(1));
    bytes32 constant IACA_ROOT = 0x2417f53cd9ead423f21f71a17726d2de8e1642521d5e8fa0bc4593240d7f2de6;
    uint256 constant NO_REFERRER = type(uint256).max;

    // The proof is bound to this address (vitalik.eth)
    address constant BOUND_ADDRESS = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;

    function run() external {
        uint256 deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

        // Load proof
        bytes memory proof = vm.readFileBinary("test/fixtures/proof.bin");

        vm.startBroadcast(deployerKey);

        // 1. Deploy all contracts
        console.log("=== DEPLOYING ===");
        HonkVerifier honk = new HonkVerifier();
        console.log("HonkVerifier:", address(honk));

        MockPriceFeed priceFeed = new MockPriceFeed(2000 * 1e8); // $2000/ETH for local testing
        console.log("MockPriceFeed:", address(priceFeed));

        ThurinSBT sbt = new ThurinSBT(address(honk), address(priceFeed));
        console.log("ThurinSBT:", address(sbt));

        ThurinVerifier verifier = new ThurinVerifier(address(honk), address(sbt));
        console.log("ThurinVerifier:", address(verifier));

        ThurinPoints points = new ThurinPoints(address(sbt), address(verifier));
        console.log("ThurinPoints:", address(points));

        // 2. Setup IACA root
        sbt.addIACARoot(IACA_ROOT, "California");
        console.log("IACA root added");

        // 3. Fund the bound address (proof is tied to vitalik.eth)
        payable(BOUND_ADDRESS).transfer(1 ether);
        console.log("Funded bound address:", BOUND_ADDRESS);

        vm.stopBroadcast();

        // 4. Mint SBT as the bound address (using unlocked account)
        console.log("");
        console.log("=== MINTING SBT ===");
        uint256 price = sbt.getMintPrice();
        console.log("Price:", price, "wei");

        vm.broadcast(BOUND_ADDRESS);
        uint256 tokenId = sbt.mint{value: price}(
            proof,
            NULLIFIER,
            ADDRESS_BINDING,
            PROOF_DATE,
            EVENT_ID,
            IACA_ROOT,
            true,  // reveal age 21+
            true,  // reveal age 18+
            true,  // reveal state
            "CA",
            NO_REFERRER
        );

        console.log("Minted token ID:", tokenId);
        console.log("Owner:", sbt.ownerOf(tokenId));
        console.log("isValid:", sbt.isValid(BOUND_ADDRESS));
        console.log("User points:", sbt.points(BOUND_ADDRESS));

        // 5. Register dApp
        console.log("");
        console.log("=== DAPP VERIFICATION ===");
        vm.broadcast(deployerKey);
        points.registerDapp("Demo dApp");
        console.log("dApp registered");

        console.log("hasValidSBT:", verifier.hasValidSBT(BOUND_ADDRESS));
        console.log("SBT expiry:", verifier.getSBTExpiry(BOUND_ADDRESS));

        console.log("");
        console.log("=== SUCCESS ===");
        console.log("Full flow completed on Anvil!");
    }
}
