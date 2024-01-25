# Summoner
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/65b43bfbebe7dc8176f84027fc17e3554a0b2583/src/Summoner.sol)

Simple summoner for Dagon (𒀭) group accounts.


## State Variables
### DAGON

```solidity
address internal constant DAGON = 0x0000000000001D4B1320bB3c47380a3D1C3A1A0C;
```


### FACTORY

```solidity
IAccounts internal constant FACTORY = IAccounts(0x000000000000dD366cc2E4432bB998e41DFD47C7);
```


## Functions
### summon


```solidity
function summon(address summoner, uint88 shares, bool locked, bytes12 salt)
    public
    payable
    returns (IAccounts account);
```

### summonForToken


```solidity
function summonForToken(address token, bool nft, uint88 threshold, bytes12 salt)
    public
    payable
    returns (IAccounts account);
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

