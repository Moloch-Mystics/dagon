# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/e32487a32d1e73c4ebea862231430b94d1c03822/src/Dagon.sol)

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

