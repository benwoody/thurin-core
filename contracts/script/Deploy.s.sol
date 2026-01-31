// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {ThurinSBT} from "../src/ThurinSBT.sol";
import {ThurinVerifier} from "../src/ThurinVerifier.sol";
import {ThurinPoints} from "../src/ThurinPoints.sol";

contract DeployScript is Script {
    // Chainlink ETH/USD price feed addresses
    address constant MAINNET_PRICE_FEED = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    address constant SEPOLIA_PRICE_FEED = 0x694AA1769357215DE4FAC081bf1f309aDC325306;

    function run() external {
        uint256 deployerPrivateKey = vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));

        // Get price feed address (default to mainnet, can override with env var)
        address priceFeed = vm.envOr("PRICE_FEED", MAINNET_PRICE_FEED);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy HonkVerifier (auto-generated ZK verifier)
        HonkVerifier honkVerifier = new HonkVerifier();
        console.log("HonkVerifier deployed at:", address(honkVerifier));

        // Deploy ThurinSBT (soulbound token for verified humans)
        ThurinSBT sbt = new ThurinSBT(address(honkVerifier), priceFeed);
        console.log("ThurinSBT deployed at:", address(sbt));

        // Deploy ThurinVerifier (dApp verification contract)
        ThurinVerifier verifier = new ThurinVerifier(address(honkVerifier), address(sbt));
        console.log("ThurinVerifier deployed at:", address(verifier));

        // Deploy ThurinPoints (points tracking for users and dApps)
        ThurinPoints points = new ThurinPoints(address(sbt), address(verifier));
        console.log("ThurinPoints deployed at:", address(points));

        // Add test IACA root (matches Prover.toml fixture)
        // This is Poseidon2(pubkey_x, pubkey_y) from the test fixture
        bytes32 testIacaRoot = 0x2417f53cd9ead423f21f71a17726d2de8e1642521d5e8fa0bc4593240d7f2de6;
        sbt.addIACARoot(testIacaRoot, "California");
        console.log("Added test IACA root:", vm.toString(testIacaRoot));

        vm.stopBroadcast();

        // Output deployment info
        console.log("");
        console.log("=== Deployment Complete ===");
        console.log("HonkVerifier:", address(honkVerifier));
        console.log("ThurinSBT:", address(sbt));
        console.log("ThurinVerifier:", address(verifier));
        console.log("ThurinPoints:", address(points));
        console.log("Owner:", vm.addr(deployerPrivateKey));
        console.log("Price Feed:", priceFeed);
        console.log("");
        console.log("Pricing (USD):");
        console.log("  Mint:", sbt.mintPriceUSD() / 1e8, "USD");
        console.log("  Renewal:", sbt.renewalPriceUSD() / 1e8, "USD");
    }
}
