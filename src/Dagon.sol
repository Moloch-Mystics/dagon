// ᗪᗩGOᑎ 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

import {ERC6909} from "@solady/src/tokens/ERC6909.sol";
import {SignatureCheckerLib} from "@solady/src/utils/SignatureCheckerLib.sol";

/// @notice Simple ownership singleton for smart accounts. Version 1x.
contract Dagon is ERC6909 {
    /// ======================= CUSTOM ERRORS ======================= ///

    /// @dev Inputs are invalid for an ownership setting.
    error InvalidSetting();

    /// =========================== EVENTS =========================== ///

    /// @dev Logs new metadata for an account ID.
    event URI(string uri, uint256 indexed id);

    /// @dev Logs new authority contract for an account.
    event AuthSet(address indexed account, IAuth auth);

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

    /// @dev The signature struct.
    struct Signature {
        address owner;
        bytes sigData;
    }

    /// @dev The account ownership settings struct.
    struct Settings {
        address token;
        uint88 threshold;
        Standard standard;
    }

    /// @dev The packed ERC4337 user operation (userOp) struct.
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
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

    /// @dev Stores mapping of voting tallies to account operation hashes.
    mapping(address account => mapping(bytes32 hash => uint256)) public votingTally;

    /// @dev Stores mapping of account owner shares cast on account operation hashes.
    mapping(address account => mapping(address owner => mapping(bytes32 hash => uint256 shares)))
        public voted;

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
        Settings memory setting = _settings[msg.sender];
        if (signature.length != 0) {
            unchecked {
                Signature[] memory signatures = abi.decode(signature, (Signature[]));
                address prev;
                address owner;
                uint256 tally;
                for (uint256 i; i != signatures.length; ++i) {
                    if (
                        SignatureCheckerLib.isValidSignatureNow(
                            owner = signatures[i].owner, hash, signatures[i].sigData
                        ) && prev < owner // Check double voting.
                    ) {
                        prev = owner;
                        tally += setting.standard == Standard.DAGON
                            ? balanceOf(owner, uint256(uint160(msg.sender)))
                            : setting.standard == Standard.ERC20 || setting.standard == Standard.ERC721
                                ? _balanceOf(setting.token, owner)
                                : _balanceOf(setting.token, owner, uint256(uint160(msg.sender)));
                    } else {
                        return 0xffffffff; // Failure code.
                    }
                }
                return _validateReturn(tally >= setting.threshold);
            }
        }
        return _validateReturn(votingTally[msg.sender][hash] >= setting.threshold);
    }

    /// @dev Validates packed userOp with additional auth logic flow among owners.
    /// note: This is expected to be called in a validator plugin-like userOp flow.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /*missingAccountFunds*/
    ) public virtual returns (uint256 validationData) {
        IAuth auth = _metadata[uint256(uint160(msg.sender))].authority;
        if (auth != IAuth(address(0))) {
            (address target, uint256 value, bytes memory data) =
                abi.decode(userOp.callData[4:], (address, uint256, bytes));
            auth.validateCall(msg.sender, target, value, data);
        }
        if (isValidSignature(userOpHash, userOp.signature) != this.isValidSignature.selector) {
            validationData = 0x01; // Failure code.
        }
    }

    /// @dev Returns validated signature result within the conventional ERC1271 syntax.
    function _validateReturn(bool success) internal pure virtual returns (bytes4 result) {
        assembly ("memory-safe") {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
    }

    /// ===================== VOTING OPERATIONS ===================== ///

    /// @dev Casts account owners' voting shares on a given operation hash.
    function vote(address account, bytes32 hash, bytes calldata signature)
        public
        virtual
        returns (uint256)
    {
        Signature[] memory signatures = abi.decode(signature, (Signature[]));
        Settings memory setting = _settings[account];
        unchecked {
            address owner;
            uint256 tally;
            for (uint256 i; i != signatures.length; ++i) {
                if (
                    SignatureCheckerLib.isValidSignatureNow(
                        owner = signatures[i].owner, hash, signatures[i].sigData
                    ) && voted[account][owner][hash] == 0 // Check double voting.
                ) {
                    tally += voted[account][owner][hash] = setting.standard == Standard.DAGON
                        ? balanceOf(owner, uint256(uint160(account)))
                        : setting.standard == Standard.ERC20 || setting.standard == Standard.ERC721
                            ? _balanceOf(setting.token, owner)
                            : _balanceOf(setting.token, owner, uint256(uint160(account)));
                }
            }
            return votingTally[account][hash] += tally; // Return latest total tally.
        }
    }

    /// @dev Casts caller voting shares on a given operation hash and returns tally.
    function vote(address account, bytes32 hash) public virtual returns (uint256) {
        if (voted[account][msg.sender][hash] != 0) revert InsufficientPermission();
        Settings storage setting = _settings[account];
        unchecked {
            return votingTally[account][hash] += voted[account][msg.sender][hash] = setting.standard
                == Standard.DAGON
                ? balanceOf(msg.sender, uint256(uint160(account)))
                : setting.standard == Standard.ERC20 || setting.standard == Standard.ERC721
                    ? _balanceOf(setting.token, msg.sender)
                    : _balanceOf(setting.token, msg.sender, uint256(uint160(account)));
        }
    }

    /// ======================== INSTALLATION ======================== ///

    /// @dev Initializes ownership settings for the caller account.
    /// note: Finalizes with transfer request in two-step pattern.
    /// See, e.g., Ownable.sol:
    /// https://github.com/Vectorized/solady/blob/main/src/auth/Ownable.sol
    function install(Ownership[] calldata owners, Settings calldata setting, Metadata calldata meta)
        public
        virtual
    {
        uint256 id = uint256(uint160(msg.sender));
        if (owners.length != 0) {
            uint96 supply;
            for (uint256 i; i != owners.length; ++i) {
                supply += owners[i].shares;
                _mint(owners[i].owner, id, owners[i].shares);
            }
            _metadata[id].totalSupply += supply;
        }
        setToken(setting.token, setting.standard);
        setThreshold(setting.threshold);
        if (bytes(meta.name).length != 0) {
            _metadata[id].name = meta.name;
            _metadata[id].symbol = meta.symbol;
        }
        if (bytes(meta.tokenURI).length != 0) setURI(meta.tokenURI);
        if (meta.authority != IAuth(address(0))) setAuth(meta.authority);
        try IOwnable(msg.sender).requestOwnershipHandover() {} catch {} // Avoid revert.
    }

    /// ===================== OWNERSHIP SETTINGS ===================== ///

    /// @dev Returns the account settings.
    function getSettings(address account) public view virtual returns (address, uint88, Standard) {
        Settings storage set = _settings[account];
        return (set.token, set.threshold, set.standard);
    }

    /// @dev Sets new authority contract for the caller account.
    function setAuth(IAuth auth) public virtual {
        emit AuthSet(msg.sender, (_metadata[uint256(uint160(msg.sender))].authority = auth));
    }

    /// @dev Sets new token ownership interface standard for the caller account.
    function setToken(address token, Standard standard) public virtual {
        emit TokenSet(
            msg.sender,
            _settings[msg.sender].token = token,
            _settings[msg.sender].standard = standard
        );
    }

    /// @dev Sets new ownership threshold for the caller account.
    function setThreshold(uint88 threshold) public virtual {
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
    function mint(address owner, uint96 shares) public virtual {
        uint256 id = uint256(uint160(msg.sender));
        _metadata[id].totalSupply += shares;
        _mint(owner, id, shares);
    }

    /// @dev Burns shares from an owner of the caller account.
    function burn(address owner, uint96 shares) public virtual {
        uint256 id = uint256(uint160(msg.sender));
        unchecked {
            if (_settings[msg.sender].threshold > (_metadata[id].totalSupply -= shares)) {
                revert InvalidSetting();
            }
        }
        _burn(owner, id, shares);
    }

    /// @dev Sets new token URI metadata for the caller account.
    function setURI(string calldata uri) public virtual {
        uint256 id = uint256(uint160(msg.sender));
        emit URI((_metadata[id].tokenURI = uri), id);
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
            mstore(0x00, 0x70a08231000000000000000000000000) // `balanceOf(address)`.
            mstore(0x14, account) // Store the `account` argument.
            pop(staticcall(gas(), token, 0x10, 0x24, 0x20, 0x20))
            amount := mload(0x20)
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
            mstore(0x00, 0x00fdd58e000000000000000000000000) // `balanceOf(address,uint256)`.
            mstore(0x14, account) // Store the `account` argument.
            mstore(0x34, id) // Store the `id` argument.
            pop(staticcall(gas(), token, 0x10, 0x44, 0x20, 0x20))
            amount := mload(0x20)
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
        }
    }

    /// @dev Returns the total supply of ERC20/721 `token`.
    function _totalSupply(address token) internal view virtual returns (uint256 supply) {
        assembly ("memory-safe") {
            mstore(0x00, 0x18160ddd) // `totalSupply()`.
            pop(staticcall(gas(), token, 0x1c, 0x04, 0x20, 0x20))
            supply := mload(0x20)
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
            mstore(0x00, 0xbd85b039) // `totalSupply(uint256)`.
            mstore(0x20, id) // Store the `id` argument.
            pop(staticcall(gas(), token, 0x1c, 0x24, 0x20, 0x20))
            supply := mload(0x20)
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
