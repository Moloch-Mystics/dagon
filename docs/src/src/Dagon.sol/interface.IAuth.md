# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/d39dde7073476515dbf75345b60f2ea3d623186a/src/Dagon.sol)

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

