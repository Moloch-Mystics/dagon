# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/d1a46b5b5c5a2b934862fab00dc866a8f0b25f91/src/Dagon.sol)

Simple authority interface for contracts.


## Functions
### validateTransfer


```solidity
function validateTransfer(address, address, uint256, uint256) external payable returns (uint256);
```

### validateCall


```solidity
function validateCall(address, address, uint256, bytes calldata)
    external
    payable
    returns (uint256);
```

