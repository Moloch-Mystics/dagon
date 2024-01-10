// ᗪᗩGOᑎ 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {ERC6909} from "@solady/src/tokens/ERC6909.sol";
import {SignatureCheckerLib} from "@solady/src/utils/SignatureCheckerLib.sol";

/// @notice Simple ownership singleton for smart accounts.
/// @dev Integration is best by means of the ERC173 and ERC1271 methods.
/// @custom:version 0.0.0
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
    event TokenSet(address indexed account, address token, Standard standard);

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
        address token;
        uint88 threshold;
        Standard standard;
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
    enum Standard {
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

    /// ================= ERC6909 METADATA & SUPPLY ================= ///

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
                for (uint256 i; i != signature.length / 85; ++i) {
                    if (
                        SignatureCheckerLib.isValidSignatureNow(
                            owner = address(bytes20(signature[pos:pos + 20])),
                            hash,
                            signature[pos + 20:pos + 85]
                        ) && prev < owner // Check double voting.
                    ) {
                        pos += 85;
                        prev = owner;
                        tally += set.standard == Standard.DAGON
                            ? balanceOf(owner, uint256(uint160(msg.sender)))
                            : set.standard == Standard.ERC20 || set.standard == Standard.ERC721
                                ? _balanceOf(set.token, owner)
                                : _balanceOf(set.token, owner, uint256(uint160(msg.sender)));
                    } else {
                        return 0xffffffff; // Failure code.
                    }
                }
                return _validateReturn(tally >= set.threshold);
            }
        }
        return _validateReturn(votingTally[hash] >= set.threshold);
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

    /// @dev Returns validated signature result within the conventional ERC1271 syntax.
    function _validateReturn(bool success) internal pure virtual returns (bytes4 result) {
        assembly {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
    }

    /// ===================== VOTING OPERATIONS ===================== ///

    /// @dev Casts account owner voting shares on a given ERC4337 userOp hash.
    function vote(address account, bytes32 userOpHash, bytes calldata signature)
        public
        payable
        virtual
        returns (uint256)
    {
        Settings memory set = _settings[account];
        bytes32 hash = SignatureCheckerLib.toEthSignedMessageHash(userOpHash);
        unchecked {
            uint256 pos;
            address owner;
            uint256 tally;
            for (uint256 i; i != signature.length / 85; ++i) {
                if (
                    SignatureCheckerLib.isValidSignatureNow(
                        owner = address(bytes20(signature[pos:pos + 20])),
                        hash,
                        signature[pos + 20:pos + 85]
                    ) && voted[owner][hash] == 0 // Check double voting.
                ) {
                    pos += 85;
                    tally += voted[owner][hash] = set.standard == Standard.DAGON
                        ? balanceOf(owner, uint256(uint160(account)))
                        : set.standard == Standard.ERC20 || set.standard == Standard.ERC721
                            ? _balanceOf(set.token, owner)
                            : _balanceOf(set.token, owner, uint256(uint160(account)));
                }
            }
            return votingTally[hash] += tally; // Return latest total tally.
        }
    }

    /// ====================== TOKEN OPERATIONS ====================== ///

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

    /// @dev Sets new token URI metadata for the caller account.
    function setURI(string calldata uri) public payable virtual {
        emit URISet(msg.sender, (_metadata[uint256(uint160(msg.sender))].tokenURI = uri));
    }

    /// ======================== INSTALLATION ======================== ///

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
            _metadata[id].totalSupply += supply;
        }
        setThreshold(setting.threshold);
        setToken(setting.token, setting.standard);
        if (bytes(meta.name).length != 0) {
            _metadata[id].name = meta.name;
            _metadata[id].symbol = meta.symbol;
        }
        if (bytes(meta.tokenURI).length != 0) setURI(meta.tokenURI);
        if (meta.authority != IAuth(address(0))) _metadata[id].authority = meta.authority;
        IOwnable(msg.sender).requestOwnershipHandover();
    }

    /// ===================== OWNERSHIP SETTINGS ===================== ///

    /// @dev Returns the account settings.
    function getSettings(address account) public view virtual returns (address, uint88, Standard) {
        Settings storage set = _settings[account];
        return (set.token, set.threshold, set.standard);
    }

    /// @dev Sets new authority contract for the caller account.
    function setAuth(IAuth auth) public payable virtual {
        emit AuthSet(msg.sender, (_metadata[uint256(uint160(msg.sender))].authority = auth));
    }

    /// @dev Sets new token ownership interface standard for the caller account.
    function setToken(address token, Standard standard) public payable virtual {
        emit TokenSet(
            msg.sender,
            _settings[msg.sender].token = token,
            _settings[msg.sender].standard = standard
        );
    }

    /// @dev Sets new ownership threshold for the caller account.
    function setThreshold(uint88 threshold) public payable virtual {
        Settings storage set = _settings[msg.sender];
        if (
            threshold
                > (
                    set.standard == Standard.DAGON
                        ? totalSupply(uint256(uint160(msg.sender)))
                        : set.standard == Standard.ERC20 || set.standard == Standard.ERC721
                            ? _totalSupply(set.token)
                            : _totalSupply(set.token, uint256(uint160(msg.sender)))
                ) || threshold == 0
        ) revert InvalidSetting();
        emit ThresholdSet(msg.sender, (set.threshold = threshold));
    }

    /// =================== EXTERNAL TOKEN HELPERS =================== ///

    /// @dev Returns the amount of ERC20/721 `token` owned by `account`.
    function _balanceOf(address token, address account)
        internal
        view
        virtual
        returns (uint256 amount)
    {
        assembly ("memory-safe") {
            mstore(0x14, account) // Store the `account` argument.
            mstore(0x00, 0x70a08231000000000000000000000000) // `balanceOf(address)`.
            if iszero(staticcall(gas(), token, 0x10, 0x24, 0x00, 0x20)) { revert(codesize(), 0x00) }
            amount := mload(0x00)
        }
    }

    /// @dev Returns the amount of ERC1155/6909 `token` `id` owned by `account`.
    function _balanceOf(address token, address account, uint256 id)
        internal
        view
        virtual
        returns (uint256 amount)
    {
        assembly ("memory-safe") {
            mstore(0x14, account) // Store the `account` argument.
            mstore(0x34, id) // Store the `id` argument.
            mstore(0x00, 0x00fdd58e000000000000000000000000) // `balanceOf(address,uint256)`.
            if iszero(staticcall(gas(), token, 0x10, 0x44, 0x00, 0x20)) { revert(codesize(), 0x00) }
            amount := mload(0x00)
            mstore(0x34, 0x00)
        }
    }

    /// @dev Returns the total supply of ERC20/721 `token`.
    function _totalSupply(address token) internal view virtual returns (uint256 supply) {
        assembly ("memory-safe") {
            mstore(0x00, 0x72dd529b000000000000000000000000) // `totalSupply()`.
            if iszero(staticcall(gas(), token, 0x10, 0x14, 0x00, 0x20)) { revert(codesize(), 0x00) }
            supply := mload(0x00)
        }
    }

    /// @dev Returns the total supply of ERC1155/6909 `token` `id`.
    function _totalSupply(address token, uint256 id)
        internal
        view
        virtual
        returns (uint256 supply)
    {
        assembly ("memory-safe") {
            mstore(0x04, id) // Store the `id` argument.
            mstore(0x00, 0x3f053e2d000000000000000000000000) // `totalSupply(uint256)`.
            if iszero(staticcall(gas(), token, 0x10, 0x24, 0x00, 0x20)) { revert(codesize(), 0x00) }
            supply := mload(0x00)
        }
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

/// @notice Simple ownership interface for handover requests.
interface IOwnable {
    function requestOwnershipHandover() external payable;
}
