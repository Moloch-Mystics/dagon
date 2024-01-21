# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/c2b041fa6461441e320461b10ebb5c5d514a6859/src/Dagon.sol)

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

