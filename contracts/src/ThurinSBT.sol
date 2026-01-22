// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IHonkVerifier} from "./interfaces/IHonkVerifier.sol";

/// @title ThurinSBT
/// @notice Soulbound token for verified mDL holders
/// @dev Non-transferable ERC721 with ZK proof verification at mint
contract ThurinSBT is ERC721, Ownable2Step {
    IHonkVerifier public immutable honkVerifier;

    // Token data
    uint256 private _tokenIdCounter;
    mapping(uint256 => uint256) public tokenMintTimestamp;
    mapping(address => uint256) public userTokenId;

    // Sybil resistance
    mapping(bytes32 => bool) public nullifierUsed;

    // IACA roots
    mapping(bytes32 => bool) public trustedIACARoots;
    mapping(bytes32 => string) public iacaStateNames;

    // Pricing (in wei)
    uint256 public mintPrice = 0.0015 ether; // ~$5 at $3333/ETH
    uint256 public renewalPrice = 0.0015 ether; // ~$5 flat for all
    uint256 public constant OG_PRICE = 0.0006 ether; // ~$2
    uint256 public constant KINDA_COOL_PRICE = 0.001 ether; // ~$3.33
    uint256 public constant OG_SUPPLY = 500;
    uint256 public constant KINDA_COOL_SUPPLY = 1500;

    // Tier tracking (for art/metadata)
    enum Tier { OG, KindaCool, Standard }
    mapping(uint256 => Tier) public tokenTier;

    // Referrals
    mapping(uint256 => uint256) public referralCount;
    mapping(uint256 => address) public referredBy;

    // Points
    mapping(address => uint256) public points;
    uint256 public constant MINT_POINTS = 100;
    uint256 public constant REFERRAL_POINTS = 50;

    // Validity
    uint256 public validityPeriod = 365 days;
    uint256 public constant PROOF_VALIDITY_PERIOD = 1 hours;
    uint256 public constant MIN_VALIDITY_PERIOD = 1 days;

    // Events
    event Minted(
        address indexed user,
        uint256 indexed tokenId,
        uint256 referrerTokenId
    );
    event IACARootAdded(bytes32 indexed root, string stateName);
    event IACARootRemoved(bytes32 indexed root);
    event MintPriceUpdated(uint256 oldPrice, uint256 newPrice);
    event RenewalPriceUpdated(uint256 oldPrice, uint256 newPrice);
    event ValidityPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event Renewed(address indexed user, uint256 indexed tokenId);

    // Errors
    error ProofFromFuture();
    error ProofExpired();
    error UntrustedIACA();
    error NullifierAlreadyUsed();
    error InvalidProof();
    error AlreadyHasSBT();
    error InsufficientPayment();
    error InvalidValidityPeriod();
    error Soulbound();
    error WithdrawFailed();
    error NoSBTToRenew();

    constructor(address _honkVerifier) ERC721("Thurin SBT", "THURIN") Ownable(msg.sender) {
        honkVerifier = IHonkVerifier(_honkVerifier);
    }

    /// @notice Get current mint price based on supply tier
    function getMintPrice() public view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply < OG_SUPPLY) return OG_PRICE;
        if (supply < KINDA_COOL_SUPPLY) return KINDA_COOL_PRICE;
        return mintPrice;
    }

    /// @notice Get current tier based on supply
    function getCurrentTier() public view returns (Tier) {
        uint256 supply = totalSupply();
        if (supply < OG_SUPPLY) return Tier.OG;
        if (supply < KINDA_COOL_SUPPLY) return Tier.KindaCool;
        return Tier.Standard;
    }

    /// @notice Get current supply (number of minted tokens)
    function totalSupply() public view returns (uint256) {
        return _tokenIdCounter;
    }

    /// @notice Mint a Thurin SBT with a valid ZK proof
    /// @param proof The ZK proof bytes
    /// @param nullifier Nullifier derived from document number
    /// @param proofTimestamp When the proof was generated
    /// @param eventId Application-specific event identifier (use 0 for SBT mint)
    /// @param iacaRoot Hash of the IACA public key used
    /// @param proveAgeOver21 Whether age_over_21 claim is proven
    /// @param proveAgeOver18 Whether age_over_18 claim is proven
    /// @param proveState Whether state claim is proven
    /// @param provenState The 2-byte state code (e.g., "CA")
    /// @param referrerTokenId Token ID of referrer (0 for no referral)
    function mint(
        bytes calldata proof,
        bytes32 nullifier,
        uint256 proofTimestamp,
        bytes32 eventId,
        bytes32 iacaRoot,
        bool proveAgeOver21,
        bool proveAgeOver18,
        bool proveState,
        bytes2 provenState,
        uint256 referrerTokenId
    ) external payable returns (uint256) {
        // Check user doesn't already have SBT
        if (balanceOf(msg.sender) > 0) revert AlreadyHasSBT();

        // Check payment
        if (msg.value < getMintPrice()) revert InsufficientPayment();

        // Freshness checks
        if (proofTimestamp > block.timestamp) revert ProofFromFuture();
        if (proofTimestamp < block.timestamp - PROOF_VALIDITY_PERIOD) revert ProofExpired();

        // Trust check
        if (!trustedIACARoots[iacaRoot]) revert UntrustedIACA();

        // Sybil check
        if (nullifierUsed[nullifier]) revert NullifierAlreadyUsed();

        // Build public inputs array (must match circuit order)
        bytes32[] memory publicInputs = new bytes32[](10);
        publicInputs[0] = nullifier;
        publicInputs[1] = bytes32(proofTimestamp);
        publicInputs[2] = eventId;
        publicInputs[3] = iacaRoot;
        publicInputs[4] = bytes32(uint256(uint160(msg.sender)));
        publicInputs[5] = bytes32(uint256(proveAgeOver21 ? 1 : 0));
        publicInputs[6] = bytes32(uint256(proveAgeOver18 ? 1 : 0));
        publicInputs[7] = bytes32(uint256(proveState ? 1 : 0));
        publicInputs[8] = bytes32(uint256(uint8(provenState[0])));
        publicInputs[9] = bytes32(uint256(uint8(provenState[1])));

        // Verify ZK proof
        if (!honkVerifier.verify(proof, publicInputs)) revert InvalidProof();

        // Mark nullifier used
        nullifierUsed[nullifier] = true;

        // Mint SBT
        uint256 tokenId = _tokenIdCounter++;
        tokenTier[tokenId] = getCurrentTier();
        _safeMint(msg.sender, tokenId);

        tokenMintTimestamp[tokenId] = block.timestamp;
        userTokenId[msg.sender] = tokenId;

        // Handle referral (use type(uint256).max for no referral instead of 0)
        if (referrerTokenId != type(uint256).max && _ownerOf(referrerTokenId) != address(0)) {
            address referrer = ownerOf(referrerTokenId);
            if (referrer != msg.sender) {
                referralCount[referrerTokenId]++;
                referredBy[tokenId] = referrer;
                points[referrer] += REFERRAL_POINTS;
            }
        }

        // Award mint points
        points[msg.sender] += MINT_POINTS;

        emit Minted(msg.sender, tokenId, referrerTokenId);

        return tokenId;
    }

    /// @notice Check if a user has a valid (non-expired) SBT
    /// @param user The address to check
    /// @return True if user has valid SBT
    function isValid(address user) external view returns (bool) {
        if (balanceOf(user) == 0) return false;

        uint256 tokenId = userTokenId[user];
        uint256 mintTime = tokenMintTimestamp[tokenId];
        return block.timestamp <= mintTime + validityPeriod;
    }

    /// @notice Get the expiry timestamp for a user's SBT
    /// @param user The address to check
    /// @return The expiry timestamp (0 if no SBT)
    function getExpiry(address user) external view returns (uint256) {
        if (balanceOf(user) == 0) return 0;

        uint256 tokenId = userTokenId[user];
        return tokenMintTimestamp[tokenId] + validityPeriod;
    }

    /// @notice Returns on-chain SVG metadata for the token
    /// @param tokenId The token ID to get metadata for
    /// @return Base64-encoded JSON metadata with embedded SVG
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);

        // Get checkmark color based on tier
        string memory checkColor;
        string memory tierName;
        Tier tier = tokenTier[tokenId];

        if (tier == Tier.OG) {
            checkColor = "#b76e79"; // Rose Gold
            tierName = "OG";
        } else if (tier == Tier.KindaCool) {
            checkColor = "#f7e7ce"; // Champagne
            tierName = "KindaCool";
        } else {
            checkColor = "#cd7f32"; // Bronze
            tierName = "Standard";
        }

        // Build SVG
        string memory svg = string(
            abi.encodePacked(
                '<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">',
                '<rect width="100" height="100" fill="#1a1a12"/>',
                '<path d="M25 80 Q25 25 50 25 Q75 25 75 50" fill="none" stroke="#7c9a3e" stroke-width="4" stroke-linecap="round"/>',
                '<path d="M33 75 Q33 35 50 35 Q67 35 67 52" fill="none" stroke="#7c9a3e" stroke-width="4" stroke-linecap="round"/>',
                '<path d="M41 70 Q41 45 50 45 Q59 45 59 55" fill="none" stroke="#c9a227" stroke-width="4" stroke-linecap="round"/>',
                '<path d="M50 65 L50 53" fill="none" stroke="#c9a227" stroke-width="4" stroke-linecap="round"/>',
                '<path d="M50 73 L55 81 L75 59" fill="none" stroke="',
                checkColor,
                '" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>',
                "</svg>"
            )
        );

        // Build JSON metadata
        string memory json = string(
            abi.encodePacked(
                '{"name": "Thurin SBT #',
                Strings.toString(tokenId),
                '", "description": "Verified human - ',
                tierName,
                ' tier", "image": "data:image/svg+xml;base64,',
                Base64.encode(bytes(svg)),
                '"}'
            )
        );

        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(json))));
    }

    /// @notice Renew an existing SBT with a fresh ZK proof
    /// @dev Requires payment and fresh proof, but allows same nullifier for existing holders
    /// @param proof The ZK proof bytes
    /// @param nullifier Nullifier derived from document number
    /// @param proofTimestamp When the proof was generated
    /// @param eventId Application-specific event identifier
    /// @param iacaRoot Hash of the IACA public key used
    /// @param proveAgeOver21 Whether age_over_21 claim is proven
    /// @param proveAgeOver18 Whether age_over_18 claim is proven
    /// @param proveState Whether state claim is proven
    /// @param provenState The 2-byte state code (e.g., "CA")
    function renew(
        bytes calldata proof,
        bytes32 nullifier,
        uint256 proofTimestamp,
        bytes32 eventId,
        bytes32 iacaRoot,
        bool proveAgeOver21,
        bool proveAgeOver18,
        bool proveState,
        bytes2 provenState
    ) external payable {
        // Must already have an SBT
        if (balanceOf(msg.sender) == 0) revert NoSBTToRenew();

        // Check payment
        if (msg.value < renewalPrice) revert InsufficientPayment();

        // Freshness checks
        if (proofTimestamp > block.timestamp) revert ProofFromFuture();
        if (proofTimestamp < block.timestamp - PROOF_VALIDITY_PERIOD) revert ProofExpired();

        // Trust check
        if (!trustedIACARoots[iacaRoot]) revert UntrustedIACA();

        // NOTE: No nullifierUsed check - same nullifier allowed for renewal

        // Build public inputs array (must match circuit order)
        bytes32[] memory publicInputs = new bytes32[](10);
        publicInputs[0] = nullifier;
        publicInputs[1] = bytes32(proofTimestamp);
        publicInputs[2] = eventId;
        publicInputs[3] = iacaRoot;
        publicInputs[4] = bytes32(uint256(uint160(msg.sender)));
        publicInputs[5] = bytes32(uint256(proveAgeOver21 ? 1 : 0));
        publicInputs[6] = bytes32(uint256(proveAgeOver18 ? 1 : 0));
        publicInputs[7] = bytes32(uint256(proveState ? 1 : 0));
        publicInputs[8] = bytes32(uint256(uint8(provenState[0])));
        publicInputs[9] = bytes32(uint256(uint8(provenState[1])));

        // Verify ZK proof
        if (!honkVerifier.verify(proof, publicInputs)) revert InvalidProof();

        // Reset validity timestamp
        uint256 tokenId = userTokenId[msg.sender];
        tokenMintTimestamp[tokenId] = block.timestamp;

        emit Renewed(msg.sender, tokenId);
    }

    // Soulbound: disable transfers
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        // Allow minting (from == 0) and burning (to == 0), but not transfers
        if (from != address(0) && to != address(0)) revert Soulbound();
        return super._update(to, tokenId, auth);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Add a trusted IACA root
    function addIACARoot(bytes32 root, string calldata stateName) external onlyOwner {
        trustedIACARoots[root] = true;
        iacaStateNames[root] = stateName;
        emit IACARootAdded(root, stateName);
    }

    /// @notice Remove a trusted IACA root
    function removeIACARoot(bytes32 root) external onlyOwner {
        trustedIACARoots[root] = false;
        delete iacaStateNames[root];
        emit IACARootRemoved(root);
    }

    /// @notice Set the standard mint price (for post-early-adopter phase)
    function setMintPrice(uint256 _mintPrice) external onlyOwner {
        uint256 oldPrice = mintPrice;
        mintPrice = _mintPrice;
        emit MintPriceUpdated(oldPrice, _mintPrice);
    }

    /// @notice Set the renewal price
    function setRenewalPrice(uint256 _renewalPrice) external onlyOwner {
        uint256 oldPrice = renewalPrice;
        renewalPrice = _renewalPrice;
        emit RenewalPriceUpdated(oldPrice, _renewalPrice);
    }

    /// @notice Set the validity period for SBTs
    function setValidityPeriod(uint256 _validityPeriod) external onlyOwner {
        if (_validityPeriod < MIN_VALIDITY_PERIOD) revert InvalidValidityPeriod();
        uint256 oldPeriod = validityPeriod;
        validityPeriod = _validityPeriod;
        emit ValidityPeriodUpdated(oldPeriod, _validityPeriod);
    }

    /// @notice Withdraw collected fees
    function withdraw() external onlyOwner {
        (bool success,) = payable(owner()).call{value: address(this).balance}("");
        if (!success) revert WithdrawFailed();
    }
}
