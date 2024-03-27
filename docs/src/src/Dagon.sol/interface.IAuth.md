# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/b2989fed9dbd3d5acc65a68f3f1f2d0fe58b892b/src/Dagon.sol)

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

