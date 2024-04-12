# Summoner
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/efc921a89c26d7bf4ef258e73ffcf64e1bdef80a/src/Summoner.sol)

Simple summoner for Dagon (𒀭) group accounts.


## State Variables
### DAGON

```solidity
address internal constant DAGON = 0x0000000000001ADDcB933DD5028159dc965b5b7f;
```


### FACTORY

```solidity
IAccounts internal constant FACTORY = IAccounts(0x000000000000dD366cc2E4432bB998e41DFD47C7);
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

