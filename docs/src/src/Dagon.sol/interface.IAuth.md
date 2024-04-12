# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/efc921a89c26d7bf4ef258e73ffcf64e1bdef80a/src/Dagon.sol)

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

