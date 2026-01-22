// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {ThurinSBT} from "../src/ThurinSBT.sol";
import {ThurinVerifier} from "../src/ThurinVerifier.sol";
import {ThurinPoints} from "../src/ThurinPoints.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));

        vm.startBroadcast(deployerPrivateKey);

        // Deploy HonkVerifier (auto-generated ZK verifier)
        HonkVerifier honkVerifier = new HonkVerifier();
        console.log("HonkVerifier deployed at:", address(honkVerifier));

        // Deploy ThurinSBT (soulbound token for verified humans)
        ThurinSBT sbt = new ThurinSBT(address(honkVerifier));
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
        console.log("");
        console.log("Pricing:");
        console.log("  OG (first 500):", sbt.OG_PRICE(), "wei (~$2)");
        console.log("  KindaCool (500-1500):", sbt.KINDA_COOL_PRICE(), "wei (~$3.33)");
        console.log("  Standard (1500+):", sbt.mintPrice(), "wei (~$5)");
        console.log("  Renewal:", sbt.renewalPrice(), "wei (~$5)");
    }
}
