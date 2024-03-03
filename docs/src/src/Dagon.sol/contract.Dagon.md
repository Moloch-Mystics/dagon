# Dagon
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/d1a46b5b5c5a2b934862fab00dc866a8f0b25f91/src/Dagon.sol)

**Inherits:**
ERC6909

Simple ownership singleton for smart accounts. Version 1.


## State Variables
### _metadata
========================== STORAGE ========================== ///

*Stores mapping of metadata settings to account token IDs.
note: IDs are unique to addresses (`uint256(uint160(account))`).*


```solidity
mapping(uint256 id => Metadata) internal _metadata;
```


### _settings
*Stores mapping of ownership settings to accounts.*


```solidity
mapping(address account => Settings) internal _settings;
```


### votingTally
*Stores mapping of voting tallies to signed userOp hashes.*


```solidity
mapping(bytes32 signedHash => uint256) public votingTally;
```


### voted
*Stores mapping of account owner voting shares cast on signed userOp hashes.*


```solidity
mapping(address owner => mapping(bytes32 signedHash => uint256 shares)) public voted;
```


## Functions
### name

================= ERC6909 METADATA & SUPPLY ================= ///

*Returns the name for token `id` using this contract.*


```solidity
function name(uint256 id) public view virtual override(ERC6909) returns (string memory);
```

### symbol

*Returns the symbol for token `id` using this contract.*


```solidity
function symbol(uint256 id) public view virtual override(ERC6909) returns (string memory);
```

### tokenURI

*Returns the URI for token `id` using this contract.*


```solidity
function tokenURI(uint256 id) public view virtual override(ERC6909) returns (string memory);
```

### totalSupply

*Returns the total supply for token `id` using this contract.*


```solidity
function totalSupply(uint256 id) public view virtual returns (uint256);
```

### constructor

======================== CONSTRUCTOR ======================== ///

*Constructs
this implementation.*


```solidity
constructor() payable;
```

### isValidSignature

=================== VALIDATION OPERATIONS =================== ///

*Validates ERC1271 signature with additional auth logic flow among owners.
note: This implementation is designed to be the ERC-173-owner-of-4337-accounts.*


```solidity
function isValidSignature(bytes32 hash, bytes calldata signature)
    public
    view
    virtual
    returns (bytes4);
```

### validateUserOp

*Validates packed userOp with additional auth logic flow among owners.
note: This is expected to be called in a validator plugin-like userOp flow.*


```solidity
function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256)
    public
    payable
    virtual
    returns (uint256 validationData);
```

### _validateReturn

*Returns validated signature result within the conventional ERC1271 syntax.*


```solidity
function _validateReturn(bool success) internal pure virtual returns (bytes4 result);
```

### vote

===================== VOTING OPERATIONS ===================== ///

*Casts account owner voting shares on a given ERC4337 userOp hash.*


```solidity
function vote(address account, bytes32 userOpHash, bytes calldata signature)
    public
    payable
    virtual
    returns (uint256);
```

### install

======================== INSTALLATION ======================== ///

*Initializes ownership settings for the caller account.
note: Finalizes with transfer request in two-step pattern.
See, e.g., Ownable.sol:
https://github.com/Vectorized/solady/blob/main/src/auth/Ownable.sol*


```solidity
function install(Ownership[] calldata owners, Settings calldata setting, Metadata calldata meta)
    public
    payable
    virtual;
```

### getSettings

===================== OWNERSHIP SETTINGS ===================== ///

*Returns the account settings.*


```solidity
function getSettings(address account) public view virtual returns (address, uint88, Standard);
```

### setAuth

*Sets new authority contract for the caller account.*


```solidity
function setAuth(IAuth auth) public payable virtual;
```

### setToken

*Sets new token ownership interface standard for the caller account.*


```solidity
function setToken(address token, Standard standard) public payable virtual;
```

### setThreshold

*Sets new ownership threshold for the caller account.*


```solidity
function setThreshold(uint88 threshold) public payable virtual;
```

### getMetadata

====================== TOKEN OPERATIONS ====================== ///

*Returns the account metadata.*


```solidity
function getMetadata(address account)
    public
    view
    virtual
    returns (string memory, string memory, string memory, IAuth);
```

### mint

*Mints shares for an owner of the caller account.*


```solidity
function mint(address owner, uint96 shares) public payable virtual;
```

### burn

*Burns shares from an owner of the caller account.*


```solidity
function burn(address owner, uint96 shares) public payable virtual;
```

### setURI

*Sets new token URI metadata for the caller account.*


```solidity
function setURI(string calldata uri) public payable virtual;
```

### _balanceOf

=================== EXTERNAL TOKEN HELPERS =================== ///

*Returns the amount of ERC20/721 `token` owned by `account`.*


```solidity
function _balanceOf(address token, address account)
    internal
    view
    virtual
    returns (uint256 amount);
```

### _balanceOf

*Returns the amount of ERC1155/6909 `token` `id` owned by `account`.*


```solidity
function _balanceOf(address token, address account, uint256 id)
    internal
    view
    virtual
    returns (uint256 amount);
```

### _totalSupply

*Returns the total supply of ERC20/721 `token`.*


```solidity
function _totalSupply(address token) internal view virtual returns (uint256 supply);
```

### _totalSupply

*Returns the total supply of ERC1155/6909 `token` `id`.*


```solidity
function _totalSupply(address token, uint256 id) internal view virtual returns (uint256 supply);
```

### _beforeTokenTransfer

========================= OVERRIDES ========================= ///

*Hook that is called before any transfer of tokens.
This includes minting and burning. Also requests authority for token transfers.*


```solidity
function _beforeTokenTransfer(address from, address to, uint256 id, uint256 amount)
    internal
    virtual
    override(ERC6909);
```

## Events
### AuthSet
=========================== EVENTS =========================== ///

*Logs new authority contract for an account.*


```solidity
event AuthSet(address indexed account, IAuth auth);
```

### URISet
*Logs new token uri settings for an account.*


```solidity
event URISet(address indexed account, string uri);
```

### ThresholdSet
*Logs new ownership threshold for an account.*


```solidity
event ThresholdSet(address indexed account, uint88 threshold);
```

### TokenSet
*Logs new token ownership standard for an account.*


```solidity
event TokenSet(address indexed account, address token, Standard standard);
```

## Errors
### InvalidSetting
======================= CUSTOM ERRORS ======================= ///

*Inputs are invalid for an ownership setting.*


```solidity
error InvalidSetting();
```

## Structs
### Metadata
========================== STRUCTS ========================== ///

*The account token metadata struct.*


```solidity
struct Metadata {
    string name;
    string symbol;
    string tokenURI;
    IAuth authority;
    uint96 totalSupply;
}
```

### Ownership
*The account ownership shares struct.*


```solidity
struct Ownership {
    address owner;
    uint96 shares;
}
```

### Settings
*The account ownership settings struct.*


```solidity
struct Settings {
    address token;
    uint88 threshold;
    Standard standard;
}
```

### PackedUserOperation
*The packed ERC4337 user operation (userOp) struct.*


```solidity
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
```

## Enums
### Standard
=========================== ENUMS =========================== ///

*The token standard interface enum.*


```solidity
enum Standard {
    DAGON,
    ERC20,
    ERC721,
    ERC1155,
    ERC6909
}
```

