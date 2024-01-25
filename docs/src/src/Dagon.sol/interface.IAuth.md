# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/61631c322dd3fa7b753c15a6c86011e828ae4ba4/src/Dagon.sol)

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

