// ᗪᗩGOᑎ 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {ERC6909} from "@solady/src/tokens/ERC6909.sol";
import {SignatureCheckerLib} from "@solady/src/utils/SignatureCheckerLib.sol";

/// @notice Simple ownership singleton for smart accounts. DAO-agnostic.
/// @dev Support for ERC-173, ERC-1271 and ERC-4337 is recommended for users.
contract Dagon is ERC6909 {
    /// ======================= CUSTOM ERRORS ======================= ///

    /// @dev Inputs are invalid for an ownership setting.
    error InvalidSetting();

    /// =========================== EVENTS =========================== ///

    /// @dev Logs new authority contract for an account.
    event AuthSet(address indexed account, IAuth auth);

    /// @dev Logs new token uri settings for an account.
    event URISet(address indexed account, string uri);

    /// @dev Logs new ownership threshold for an account.
    event ThresholdSet(address indexed account, uint88 threshold);

    /// @dev Logs new token ownership standard for an account.
    event TokenSet(address indexed account, ITokenOwner tkn, TokenStandard std);

    /// ========================== STRUCTS ========================== ///

    /// @dev The account token metadata struct.
    struct Metadata {
        string name;
        string symbol;
        string tokenURI;
        IAuth authority;
        uint96 totalSupply;
    }

    /// @dev The account ownership shares struct.
    struct Ownership {
        address owner;
        uint96 shares;
    }

    /// @dev The account ownership settings struct.
    struct Settings {
        ITokenOwner tkn;
        uint88 threshold;
        TokenStandard std;
    }

    /// @dev The ERC4337 user operation (userOp) struct.
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    /// =========================== ENUMS =========================== ///

    /// @dev The token standard interface enum.
    enum TokenStandard {
        DAGON,
        ERC20,
        ERC721,
        ERC1155,
        ERC6909
    }

    /// ========================== STORAGE ========================== ///

    /// @dev Stores mapping of metadata settings to account token IDs.
    /// note: IDs are unique to addresses (`uint256(uint160(account))`).
    mapping(uint256 id => Metadata) internal _metadata;

    /// @dev Stores mapping of ownership settings to accounts.
    mapping(address account => Settings) internal _settings;

    /// @dev Stores mapping of voting tallies to signed userOp hashes.
    mapping(bytes32 signedHash => uint256) public votingTally;

    /// @dev Stores mapping of account owner voting shares cast on signed userOp hashes.
    mapping(address owner => mapping(bytes32 signedHash => uint256 shares)) public voted;

    /// ====================== ERC6909 METADATA ====================== ///

    /// @dev Returns the name for token `id` using this contract.
    function name(uint256 id) public view virtual override(ERC6909) returns (string memory) {
        return _metadata[id].name;
    }

    /// @dev Returns the symbol for token `id` using this contract.
    function symbol(uint256 id) public view virtual override(ERC6909) returns (string memory) {
        return _metadata[id].symbol;
    }

    /// @dev Returns the URI for token `id` using this contract.
    function tokenURI(uint256 id) public view virtual override(ERC6909) returns (string memory) {
        return _metadata[id].tokenURI;
    }

    /// @dev Returns the total supply for token `id` using this contract.
    function totalSupply(uint256 id) public view virtual returns (uint256) {
        return _metadata[id].totalSupply;
    }

    /// ======================== CONSTRUCTOR ======================== ///

    /// @dev Constructs
    /// this implementation.
    constructor() payable {}

    /// =================== VALIDATION OPERATIONS =================== ///

    /// @dev Validates ERC1271 signature with additional auth logic flow among owners.
    /// note: This implementation is designed to be the ERC-173-owner-of-4337-accounts.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        virtual
        returns (bytes4)
    {
        Settings memory set = _settings[msg.sender];
        if (signature.length != 0) {
            unchecked {
                uint256 pos;
                address prev;
                address owner;
                uint256 tally;
                // Check if the owners' signature is valid:
                for (uint256 i; i != signature.length / 85; ++i) {
                    if (
                        SignatureCheckerLib.isValidSignatureNow(
                            owner = address(bytes20(signature[pos:pos + 20])),
                            hash,
                            signature[pos + 20:pos + 85]
                        ) && prev < owner
                    ) {
                        pos += 85;
                        prev = owner;
                        tally += set.std == TokenStandard.DAGON
                            ? balanceOf(owner, uint256(uint160(msg.sender)))
                            : set.std == TokenStandard.ERC20 || set.std == TokenStandard.ERC721
                                ? set.tkn.balanceOf(owner)
                                : set.tkn.balanceOf(owner, uint256(uint160(msg.sender)));
                    } else {
                        return 0xffffffff; // Failure code.
                    }
                }
                // Check if the ownership tally has been met:
                if (tally >= set.threshold) {
                    return this.isValidSignature.selector;
                } else {
                    return 0xffffffff; // Failure code.
                }
            }
        } else {
            if (votingTally[hash] >= set.threshold) {
                return this.isValidSignature.selector;
            } else {
                return 0xffffffff; // Failure code.
            }
        }
    }

    /// @dev Validates ERC4337 userOp with additional auth logic flow among owners.
    /// note: This is expected to be called in a validator plugin-like userOp flow.
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /*missingAccountFunds*/
    ) public payable virtual returns (uint256 validationData) {
        IAuth auth = _metadata[uint256(uint160(msg.sender))].authority;
        if (auth != IAuth(address(0))) {
            (address target, uint256 value, bytes memory data) =
                abi.decode(userOp.callData[4:], (address, uint256, bytes));
            auth.validateCall(msg.sender, target, value, data);
        }
        if (
            isValidSignature(
                SignatureCheckerLib.toEthSignedMessageHash(userOpHash), userOp.signature
            ) != this.isValidSignature.selector
        ) validationData = 0x01; // Failure code.
    }

    /// ===================== VOTING OPERATIONS ===================== ///

    /// @dev Casts account owner voting shares on a given ERC4337 userOp hash.
    function vote(address account, bytes32 userOpHash, bytes calldata signature)
        public
        payable
        virtual
        returns (uint256)
    {
        bytes32 hash = SignatureCheckerLib.toEthSignedMessageHash(userOpHash);
        Settings memory set = _settings[account];
        unchecked {
            uint256 pos;
            address owner;
            uint256 tally;
            // Check if the owners' signature is valid:
            for (uint256 i; i != signature.length / 85; ++i) {
                if (
                    SignatureCheckerLib.isValidSignatureNow(
                        owner = address(bytes20(signature[pos:pos + 20])),
                        hash,
                        signature[pos + 20:pos + 85]
                    ) && voted[owner][hash] == 0 // Check double voting.
                ) {
                    pos += 85;
                    tally += voted[owner][hash] = set.std == TokenStandard.DAGON
                        ? balanceOf(owner, uint256(uint160(account)))
                        : set.std == TokenStandard.ERC20 || set.std == TokenStandard.ERC721
                            ? set.tkn.balanceOf(owner)
                            : set.tkn.balanceOf(owner, uint256(uint160(account)));
                }
            }
            return votingTally[hash] += tally;
        }
    }

    /// ================== INSTALLATION OPERATIONS ================== ///

    /// @dev Initializes ownership settings for the caller account.
    /// note: Finalizes with transfer request in two-step pattern.
    /// See, e.g., Ownable.sol:
    /// https://github.com/Vectorized/solady/blob/main/src/auth/Ownable.sol
    function install(Ownership[] calldata owners, Settings calldata setting, Metadata calldata meta)
        public
        payable
        virtual
    {
        uint256 id = uint256(uint160(msg.sender));
        if (owners.length != 0) {
            uint96 supply;
            for (uint256 i; i != owners.length;) {
                _mint(owners[i].owner, id, owners[i].shares);
                supply += owners[i].shares;
                unchecked {
                    ++i;
                }
            }
            unchecked {
                _metadata[id].totalSupply += supply;
            }
        }
        setToken(setting.tkn, setting.std);
        setThreshold(setting.threshold);
        if (bytes(meta.tokenURI).length != 0) setURI(meta.tokenURI);
        if (bytes(meta.name).length != 0) {
            _metadata[id].name = meta.name;
            _metadata[id].symbol = meta.symbol;
        }
        if (meta.authority != IAuth(address(0))) _metadata[id].authority = meta.authority;
        IOwnable(msg.sender).requestOwnershipHandover();
    }

    /// ====================== TOKEN OPERATIONS ====================== ///

    /// @dev Mints shares for an owner of the caller account.
    function mint(address owner, uint96 shares) public payable virtual {
        uint256 id = uint256(uint160(msg.sender));
        _metadata[id].totalSupply += shares;
        _mint(owner, id, shares);
    }

    /// @dev Burns shares from an owner of the caller account.
    function burn(address owner, uint96 shares) public payable virtual {
        uint256 id = uint256(uint160(msg.sender));
        unchecked {
            if (_settings[msg.sender].threshold > (_metadata[id].totalSupply -= shares)) {
                revert InvalidSetting();
            }
        }
        _burn(owner, id, shares);
    }

    /// ===================== OWNERSHIP SETTINGS ===================== ///

    /// @dev Returns the account settings.
    function getSettings(address account)
        public
        view
        virtual
        returns (ITokenOwner, uint88, TokenStandard)
    {
        Settings storage set = _settings[account];
        return (set.tkn, set.threshold, set.std);
    }

    /// @dev Returns the account metadata.
    function getMetadata(address account)
        public
        view
        virtual
        returns (string memory, string memory, string memory, IAuth)
    {
        Metadata storage meta = _metadata[uint256(uint160(account))];
        return (meta.name, meta.symbol, meta.tokenURI, meta.authority);
    }

    /// @dev Sets new authority contract for the caller account.
    function setAuth(IAuth auth) public payable virtual {
        emit AuthSet(msg.sender, (_metadata[uint256(uint160(msg.sender))].authority = auth));
    }

    /// @dev Sets new ownership threshold for the caller account.
    function setThreshold(uint88 threshold) public payable virtual {
        Settings storage set = _settings[msg.sender];
        if (
            threshold
                > (
                    set.std == TokenStandard.DAGON
                        ? totalSupply(uint256(uint160(msg.sender)))
                        : set.std == TokenStandard.ERC20 || set.std == TokenStandard.ERC721
                            ? set.tkn.totalSupply()
                            : set.tkn.totalSupply(uint256(uint160(msg.sender)))
                ) || threshold == 0
        ) revert InvalidSetting();
        emit ThresholdSet(msg.sender, (set.threshold = threshold));
    }

    /// @dev Sets new token ownership interface standard for the caller account.
    function setToken(ITokenOwner tkn, TokenStandard std) public payable virtual {
        emit TokenSet(msg.sender, _settings[msg.sender].tkn = tkn, _settings[msg.sender].std = std);
    }

    /// @dev Sets new token URI metadata for the caller account.
    function setURI(string calldata uri) public payable virtual {
        emit URISet(msg.sender, (_metadata[uint256(uint160(msg.sender))].tokenURI = uri));
    }

    /// ========================= OVERRIDES ========================= ///

    /// @dev Hook that is called before any transfer of tokens.
    /// This includes minting and burning. Also requests authority for token transfers.
    function _beforeTokenTransfer(address from, address to, uint256 id, uint256 amount)
        internal
        virtual
        override(ERC6909)
    {
        IAuth auth = _metadata[id].authority;
        if (auth != IAuth(address(0))) auth.validateTransfer(from, to, id, amount);
    }
}

/// @notice Simple interface for ownership requests.
interface IOwnable {
    function requestOwnershipHandover() external payable;
}

/// @notice Simple authority interface for contracts.
interface IAuth {
    function validateTransfer(address, address, uint256, uint256)
        external
        payable
        returns (uint256);
    function validateCall(address, address, uint256, bytes calldata)
        external
        payable
        returns (uint256);
}

/// @notice Generalized fungible token ownership interface.
interface ITokenOwner {
    function balanceOf(address) external view returns (uint256);
    function balanceOf(address, uint256) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalSupply(uint256) external view returns (uint256);
}
