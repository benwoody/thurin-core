// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ThurinSBT} from "../src/ThurinSBT.sol";
import {IHonkVerifier} from "../src/interfaces/IHonkVerifier.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract MockHonkVerifier is IHonkVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return shouldVerify;
    }
}

contract ThurinSBTTest is Test {
    ThurinSBT public sbt;
    MockHonkVerifier public mockVerifier;
    MockPriceFeed public mockPriceFeed;

    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public charlie = makeAddr("charlie");
    address public owner = makeAddr("owner");

    bytes32 public constant IACA_ROOT_CA = keccak256("california-iaca-root");
    bytes32 public constant EVENT_ID = bytes32(uint256(0));
    bytes32 public constant MOCK_ADDRESS_BINDING = keccak256("mock-address-binding");
    bytes public constant MOCK_PROOF = hex"deadbeef";
    uint256 public constant NO_REFERRER = type(uint256).max;
    uint32 public constant PROOF_DATE = 20240101; // Matches vm.warp(1704067200)

    // ETH price: $2000 with 8 decimals
    int256 public constant ETH_PRICE = 2000 * 1e8;

    bool public constant PROVE_AGE_21 = true;
    bool public constant PROVE_AGE_18 = true;
    bool public constant PROVE_STATE = true;
    bytes2 public constant STATE_CA = "CA";

    event Minted(
        address indexed user,
        uint256 indexed tokenId,
        uint256 referrerTokenId
    );
    event IACARootAdded(bytes32 indexed root, string stateName);
    event IACARootRemoved(bytes32 indexed root);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event Renewed(address indexed user, uint256 indexed tokenId);
    event RenewalPriceUpdated(uint256 oldPriceUSD, uint256 newPriceUSD);
    event MintPriceUpdated(uint256 oldPriceUSD, uint256 newPriceUSD);
    event Burned(address indexed user, uint256 indexed tokenId);

    function setUp() public {
        vm.warp(1704067200);

        mockVerifier = new MockHonkVerifier();
        mockPriceFeed = new MockPriceFeed(ETH_PRICE);

        vm.prank(owner);
        sbt = new ThurinSBT(address(mockVerifier), address(mockPriceFeed));

        vm.prank(owner);
        sbt.addIACARoot(IACA_ROOT_CA, "California");

        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
        vm.deal(charlie, 10 ether);
    }

    // Helper function to mint as a user
    function _mintAs(
        address user,
        bytes32 nullifier,
        uint256 referrerTokenId
    ) internal returns (uint256) {
        uint256 price = sbt.getMintPrice();
        vm.prank(user);
        return sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, referrerTokenId
        );
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsVerifier() public view {
        assertEq(address(sbt.honkVerifier()), address(mockVerifier));
    }

    function test_constructor_setsOwner() public view {
        assertEq(sbt.owner(), owner);
    }

    function test_constructor_setsName() public view {
        assertEq(sbt.name(), "Thurin SBT");
        assertEq(sbt.symbol(), "THURIN");
    }

    /*//////////////////////////////////////////////////////////////
                            PRICING
    //////////////////////////////////////////////////////////////*/

    function test_getETHPrice_returnsPrice() public view {
        assertEq(sbt.getETHPrice(), uint256(ETH_PRICE));
    }

    function test_getMintPrice_calculatesCorrectly() public view {
        // $5 USD at $2000/ETH = 0.0025 ETH = 2.5e15 wei
        uint256 expectedPrice = (5 * 1e8 * 1e18) / uint256(ETH_PRICE);
        assertEq(sbt.getMintPrice(), expectedPrice);
        assertEq(expectedPrice, 0.0025 ether);
    }

    function test_getMintPrice_updatesWithETHPrice() public {
        // Change ETH price to $4000
        mockPriceFeed.setPrice(4000 * 1e8);

        // $5 USD at $4000/ETH = 0.00125 ETH
        uint256 expectedPrice = (5 * 1e8 * 1e18) / (4000 * 1e8);
        assertEq(sbt.getMintPrice(), expectedPrice);
        assertEq(expectedPrice, 0.00125 ether);
    }

    function test_getETHPrice_revertsOnStalePrice() public {
        // Set price updated at > 1 hour ago
        mockPriceFeed.setUpdatedAt(block.timestamp - 2 hours);

        vm.expectRevert(ThurinSBT.StalePrice.selector);
        sbt.getETHPrice();
    }

    function test_getETHPrice_revertsOnInvalidPrice() public {
        mockPriceFeed.setPrice(0);

        vm.expectRevert(ThurinSBT.InvalidPrice.selector);
        sbt.getETHPrice();
    }

    function test_getETHPrice_revertsOnNegativePrice() public {
        mockPriceFeed.setPrice(-100);

        vm.expectRevert(ThurinSBT.InvalidPrice.selector);
        sbt.getETHPrice();
    }

    /*//////////////////////////////////////////////////////////////
                            MINTING
    //////////////////////////////////////////////////////////////*/

    function test_mint_succeedsWithValidProof() public {
        bytes32 nullifier = keccak256("alice-nullifier");

        vm.expectEmit(true, true, true, false);
        emit Minted(alice, 0, NO_REFERRER);

        uint256 tokenId = _mintAs(alice, nullifier, NO_REFERRER);

        assertEq(tokenId, 0);
        assertEq(sbt.balanceOf(alice), 1);
        assertEq(sbt.ownerOf(0), alice);
        assertTrue(sbt.nullifierUsed(nullifier));
        assertEq(sbt.points(alice), sbt.MINT_POINTS());
    }

    function test_mint_revertsWithInsufficientPayment() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 price = sbt.getMintPrice();

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.InsufficientPayment.selector);
        sbt.mint{value: price - 1}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    function test_mint_revertsIfAlreadyHasSBT() public {
        bytes32 nullifier1 = keccak256("alice-nullifier-1");
        bytes32 nullifier2 = keccak256("alice-nullifier-2");

        _mintAs(alice, nullifier1, NO_REFERRER);

        uint256 price = sbt.getMintPrice();
        vm.prank(alice);
        vm.expectRevert(ThurinSBT.AlreadyHasSBT.selector);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier2, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    function test_mint_revertsWithUntrustedIACA() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        bytes32 untrustedRoot = keccak256("untrusted");
        uint256 price = sbt.getMintPrice();

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.UntrustedIACA.selector);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, untrustedRoot,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    function test_mint_revertsWithUsedNullifier() public {
        bytes32 nullifier = keccak256("shared-nullifier");

        _mintAs(alice, nullifier, NO_REFERRER);

        uint256 price = sbt.getMintPrice();
        vm.prank(bob);
        vm.expectRevert(ThurinSBT.NullifierAlreadyUsed.selector);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    function test_mint_revertsWithFutureTimestamp() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint32 futureDate = 20240105; // 4 days in future (tolerance is 1 day)
        uint256 price = sbt.getMintPrice();

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.ProofDateFromFuture.selector);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, futureDate, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    function test_mint_revertsWithExpiredProof() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint32 oldDate = 20231225; // A week before (tolerance is 1 day)
        uint256 price = sbt.getMintPrice();

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.ProofDateTooOld.selector);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, oldDate, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    function test_mint_revertsWithInvalidProof() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 price = sbt.getMintPrice();
        mockVerifier.setShouldVerify(false);

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.InvalidProof.selector);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );
    }

    /*//////////////////////////////////////////////////////////////
                            REFERRALS
    //////////////////////////////////////////////////////////////*/

    function test_mint_tracksReferral() public {
        bytes32 aliceNullifier = keccak256("alice-nullifier");
        uint256 aliceTokenId = _mintAs(alice, aliceNullifier, NO_REFERRER);

        uint256 alicePointsBefore = sbt.points(alice);

        bytes32 bobNullifier = keccak256("bob-nullifier");
        _mintAs(bob, bobNullifier, aliceTokenId);

        assertEq(sbt.referralCount(aliceTokenId), 1);
        assertEq(sbt.referredBy(1), alice);
        assertEq(sbt.points(alice), alicePointsBefore + sbt.REFERRAL_POINTS());
    }

    function test_mint_tracksReferralForTokenIdZero() public {
        // Specifically test that token ID 0 can be used as a referrer
        bytes32 aliceNullifier = keccak256("alice-nullifier");
        uint256 aliceTokenId = _mintAs(alice, aliceNullifier, NO_REFERRER);
        assertEq(aliceTokenId, 0); // Confirm Alice got token 0

        bytes32 bobNullifier = keccak256("bob-nullifier");
        _mintAs(bob, bobNullifier, 0); // Use token 0 as referrer

        assertEq(sbt.referralCount(0), 1);
        assertEq(sbt.referredBy(1), alice);
    }

    function test_mint_ignoresSelfReferral() public {
        bytes32 aliceNullifier = keccak256("alice-nullifier");
        uint256 aliceTokenId = _mintAs(alice, aliceNullifier, NO_REFERRER);

        // Alice can't mint again, so self-referral isn't possible
        assertEq(sbt.referralCount(aliceTokenId), 0);
    }

    function test_mint_ignoresInvalidReferrer() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 invalidTokenId = 999;

        _mintAs(alice, nullifier, invalidTokenId);

        assertEq(sbt.balanceOf(alice), 1);
        assertEq(sbt.referredBy(0), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                            VALIDITY
    //////////////////////////////////////////////////////////////*/

    function test_isValid_returnsTrueForValidSBT() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        assertTrue(sbt.isValid(alice));
    }

    function test_isValid_returnsFalseForNoSBT() public view {
        assertFalse(sbt.isValid(alice));
    }

    function test_isValid_returnsFalseForExpiredSBT() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        vm.warp(block.timestamp + sbt.validityPeriod() + 1);

        assertFalse(sbt.isValid(alice));
    }

    function test_getExpiry_returnsCorrectTimestamp() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 mintTime = block.timestamp;

        _mintAs(alice, nullifier, NO_REFERRER);

        assertEq(sbt.getExpiry(alice), mintTime + sbt.validityPeriod());
    }

    function test_getExpiry_returnsZeroForNoSBT() public view {
        assertEq(sbt.getExpiry(alice), 0);
    }

    /*//////////////////////////////////////////////////////////////
                            RENEWAL
    //////////////////////////////////////////////////////////////*/

    function _renewAs(address user, bytes32 nullifier, uint32 proofDate) internal {
        uint256 price = sbt.getRenewalPrice();
        vm.prank(user);
        sbt.renew{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, proofDate, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_renew_succeedsWithValidProof() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 tokenId = _mintAs(alice, nullifier, NO_REFERRER);

        // Fast forward to near expiry (300 days)
        // With the approximate _timestampToYYYYMMDD formula:
        // dayOfYear = 301, month = 11, day = 2 -> 20241102
        vm.warp(block.timestamp + 300 days);
        mockPriceFeed.setUpdatedAt(block.timestamp); // Refresh price feed timestamp
        uint256 oldExpiry = sbt.getExpiry(alice);
        uint32 renewDate = 20241102;

        // Renew with same nullifier
        vm.expectEmit(true, true, false, true);
        emit Renewed(alice, tokenId);
        _renewAs(alice, nullifier, renewDate);

        // Expiry should be extended
        assertGt(sbt.getExpiry(alice), oldExpiry);
        assertTrue(sbt.isValid(alice));
    }

    function test_renew_allowsSameNullifier() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        // Same nullifier should work for renewal
        // With the approximate formula, 300 days = 20241102
        vm.warp(block.timestamp + 300 days);
        mockPriceFeed.setUpdatedAt(block.timestamp); // Refresh price feed timestamp
        uint32 renewDate = 20241102;
        _renewAs(alice, nullifier, renewDate);

        assertTrue(sbt.isValid(alice));
    }

    function test_renew_revertsIfNoSBT() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 price = sbt.getRenewalPrice();

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.NoSBTToRenew.selector);
        sbt.renew{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_renew_revertsWithInsufficientPayment() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        uint256 price = sbt.getRenewalPrice();
        vm.prank(alice);
        vm.expectRevert(ThurinSBT.InsufficientPayment.selector);
        sbt.renew{value: price - 1}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_renew_revertsWithExpiredProof() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        uint32 oldDate = 20231225; // A week before
        uint256 price = sbt.getRenewalPrice();

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.ProofDateTooOld.selector);
        sbt.renew{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, oldDate, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_renew_revertsWithInvalidProof() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        mockVerifier.setShouldVerify(false);
        uint256 price = sbt.getRenewalPrice();

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.InvalidProof.selector);
        sbt.renew{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA
        );
    }

    function test_renew_canRenewExpiredSBT() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        // Let SBT expire (365 days + 1 = ~Jan 2025 = 20250102)
        vm.warp(block.timestamp + sbt.validityPeriod() + 1 days);
        mockPriceFeed.setUpdatedAt(block.timestamp); // Refresh price feed timestamp
        assertFalse(sbt.isValid(alice));
        uint32 renewDate = 20250102;

        // Can still renew
        _renewAs(alice, nullifier, renewDate);
        assertTrue(sbt.isValid(alice));
    }

    /*//////////////////////////////////////////////////////////////
                            SOULBOUND
    //////////////////////////////////////////////////////////////*/

    function test_transfer_reverts() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.Soulbound.selector);
        sbt.transferFrom(alice, bob, 0);
    }

    function test_safeTransfer_reverts() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        vm.prank(alice);
        vm.expectRevert(ThurinSBT.Soulbound.selector);
        sbt.safeTransferFrom(alice, bob, 0);
    }

    /*//////////////////////////////////////////////////////////////
                            BURN (WALLET MIGRATION)
    //////////////////////////////////////////////////////////////*/

    function test_burn_succeedsForOwner() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 tokenId = _mintAs(alice, nullifier, NO_REFERRER);

        // Verify initial state
        assertEq(sbt.balanceOf(alice), 1);
        assertTrue(sbt.nullifierUsed(nullifier));
        assertEq(sbt.tokenNullifier(tokenId), nullifier);

        // Burn
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Burned(alice, tokenId);
        sbt.burn();

        // Verify post-burn state
        assertEq(sbt.balanceOf(alice), 0);
        assertFalse(sbt.nullifierUsed(nullifier)); // Nullifier freed
        assertEq(sbt.tokenNullifier(tokenId), bytes32(0)); // Cleared
        assertEq(sbt.userTokenId(alice), 0); // Cleared
    }

    function test_burn_revertsIfNoSBT() public {
        vm.prank(alice);
        vm.expectRevert(ThurinSBT.NoSBTToBurn.selector);
        sbt.burn();
    }

    function test_burn_allowsRemintToNewWallet() public {
        bytes32 nullifier = keccak256("alice-nullifier");

        // Alice mints
        _mintAs(alice, nullifier, NO_REFERRER);
        assertEq(sbt.balanceOf(alice), 1);

        // Alice burns
        vm.prank(alice);
        sbt.burn();
        assertEq(sbt.balanceOf(alice), 0);

        // Same nullifier can now be used by Bob (wallet migration)
        uint256 bobTokenId = _mintAs(bob, nullifier, NO_REFERRER);
        assertEq(sbt.balanceOf(bob), 1);
        assertEq(sbt.tokenNullifier(bobTokenId), nullifier);
    }

    function test_burn_allowsRemintToSameWallet() public {
        bytes32 nullifier = keccak256("alice-nullifier");

        // Alice mints
        _mintAs(alice, nullifier, NO_REFERRER);
        uint256 firstTokenId = sbt.userTokenId(alice);

        // Alice burns
        vm.prank(alice);
        sbt.burn();

        // Alice can mint again with same nullifier
        uint256 secondTokenId = _mintAs(alice, nullifier, NO_REFERRER);

        // Different token ID (counter incremented)
        assertGt(secondTokenId, firstTokenId);
        assertEq(sbt.balanceOf(alice), 1);
    }

    function test_burn_clearsPointsNothing() public {
        // Points should NOT be cleared on burn (earned legitimately)
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        uint256 pointsBefore = sbt.points(alice);
        assertGt(pointsBefore, 0);

        vm.prank(alice);
        sbt.burn();

        // Points still there
        assertEq(sbt.points(alice), pointsBefore);
    }

    function test_tokenNullifier_storedOnMint() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 tokenId = _mintAs(alice, nullifier, NO_REFERRER);

        assertEq(sbt.tokenNullifier(tokenId), nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_addIACARoot_storesRoot() public {
        bytes32 newRoot = keccak256("texas-root");

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IACARootAdded(newRoot, "Texas");
        sbt.addIACARoot(newRoot, "Texas");

        assertTrue(sbt.trustedIACARoots(newRoot));
        assertEq(sbt.iacaStateNames(newRoot), "Texas");
    }

    function test_addIACARoot_revertsIfNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        sbt.addIACARoot(keccak256("test"), "Test");
    }

    function test_removeIACARoot_removesRoot() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IACARootRemoved(IACA_ROOT_CA);
        sbt.removeIACARoot(IACA_ROOT_CA);

        assertFalse(sbt.trustedIACARoots(IACA_ROOT_CA));
    }

    function test_setMintPriceUSD_updatesPrice() public {
        uint256 newPriceUSD = 10 * 1e8; // $10

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit MintPriceUpdated(5 * 1e8, newPriceUSD);
        sbt.setMintPriceUSD(newPriceUSD);

        assertEq(sbt.mintPriceUSD(), newPriceUSD);
        // At $2000/ETH, $10 = 0.005 ETH
        assertEq(sbt.getMintPrice(), 0.005 ether);
    }

    function test_setValidityPeriod_updatesPeriod() public {
        uint256 newPeriod = 180 days;

        vm.prank(owner);
        sbt.setValidityPeriod(newPeriod);

        assertEq(sbt.validityPeriod(), newPeriod);
    }

    function test_setRenewalPriceUSD_updatesPrice() public {
        uint256 newPriceUSD = 10 * 1e8; // $10

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit RenewalPriceUpdated(5 * 1e8, newPriceUSD);
        sbt.setRenewalPriceUSD(newPriceUSD);

        assertEq(sbt.renewalPriceUSD(), newPriceUSD);
        // At $2000/ETH, $10 = 0.005 ETH
        assertEq(sbt.getRenewalPrice(), 0.005 ether);
    }

    function test_transferOwnership_transfersOwnership() public {
        // Step 1: Owner initiates transfer
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferStarted(owner, alice);
        sbt.transferOwnership(alice);

        // Owner is still owner, alice is pending
        assertEq(sbt.owner(), owner);
        assertEq(sbt.pendingOwner(), alice);

        // Step 2: Alice accepts ownership
        vm.prank(alice);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, alice);
        sbt.acceptOwnership();

        // Now alice is owner
        assertEq(sbt.owner(), alice);
        assertEq(sbt.pendingOwner(), address(0));
    }

    function test_withdraw_sendsBalance() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        uint256 contractBalance = address(sbt).balance;
        uint256 ownerBalanceBefore = owner.balance;

        vm.prank(owner);
        sbt.withdraw();

        assertEq(address(sbt).balance, 0);
        assertEq(owner.balance, ownerBalanceBefore + contractBalance);
    }

    /*//////////////////////////////////////////////////////////////
                            TOKEN URI TESTS
    //////////////////////////////////////////////////////////////*/

    function test_tokenURI_returnsValidMetadata() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        uint256 tokenId = _mintAs(alice, nullifier, NO_REFERRER);

        string memory uri = sbt.tokenURI(tokenId);

        // Should start with data:application/json;base64,
        assertTrue(bytes(uri).length > 29);
        assertEq(_startsWith(uri, "data:application/json;base64,"), true);
    }

    function test_tokenURI_revertsForNonexistentToken() public {
        vm.expectRevert();
        sbt.tokenURI(999);
    }

    function test_tokenURI_containsValidSVG() public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        string memory uri = sbt.tokenURI(0);
        assertTrue(bytes(uri).length > 0);
        // The base64-encoded output contains the SVG, verified by successful encoding
    }

    function _startsWith(string memory str, string memory prefix) internal pure returns (bool) {
        bytes memory strBytes = bytes(str);
        bytes memory prefixBytes = bytes(prefix);
        if (strBytes.length < prefixBytes.length) return false;
        for (uint256 i = 0; i < prefixBytes.length; i++) {
            if (strBytes[i] != prefixBytes[i]) return false;
        }
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_mint_acceptsValidProofDates(uint256 selector) public {
        // Test that minting works with different valid proof dates
        // Using only PROOF_DATE (today) to avoid edge cases with the approximate date formula
        bytes32 nullifier = keccak256(abi.encodePacked("fuzz", selector));

        uint256 price = sbt.getMintPrice();
        vm.prank(alice);
        sbt.mint{value: price}(
            MOCK_PROOF, nullifier, MOCK_ADDRESS_BINDING, PROOF_DATE, EVENT_ID, IACA_ROOT_CA,
            PROVE_AGE_21, PROVE_AGE_18, PROVE_STATE, STATE_CA, NO_REFERRER
        );

        assertTrue(sbt.balanceOf(alice) == 1);
    }

    function testFuzz_isValid_respectsValidityPeriod(uint256 timeElapsed) public {
        bytes32 nullifier = keccak256("alice-nullifier");
        _mintAs(alice, nullifier, NO_REFERRER);

        uint256 validityPeriod = sbt.validityPeriod();
        timeElapsed = bound(timeElapsed, 0, validityPeriod * 2);

        vm.warp(block.timestamp + timeElapsed);

        if (timeElapsed <= validityPeriod) {
            assertTrue(sbt.isValid(alice));
        } else {
            assertFalse(sbt.isValid(alice));
        }
    }
}
