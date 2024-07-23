# Summoner
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/d39dde7073476515dbf75345b60f2ea3d623186a/src/Summoner.sol)

Simple summoner for Dagon (𒀭) group accounts.


## State Variables
### DAGON

```solidity
address internal constant DAGON = 0x000000000000FEb893BB5D63bA33323EdCC237cE;
```


### FACTORY

```solidity
IAccounts internal constant FACTORY = IAccounts(0x0000000000009f1E546FC4A8F68eB98031846cb8);
```


## Functions
### summon


```solidity
function summon(Ownership[] calldata summoners, uint88 threshold, bool locked, bytes12 salt)
    public
    payable
    returns (IAccounts account);
```

### summonForToken


```solidity
function summonForToken(address token, Standard standard, uint88 threshold, bytes12 salt)
    public
    payable
    returns (IAccounts account);
```

## Structs
### Ownership

```solidity
struct Ownership {
    address owner;
    uint96 shares;
}
```

## Enums
### Standard

```solidity
enum Standard {
    DAGON,
    ERC20,
    ERC721,
    ERC1155,
    ERC6909
}
```

