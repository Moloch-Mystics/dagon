# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/405e4eb5a2a407d3f2421047d8b8f778ad336343/src/Dagon.sol)

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

