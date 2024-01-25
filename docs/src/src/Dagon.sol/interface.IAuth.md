# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/65b43bfbebe7dc8176f84027fc17e3554a0b2583/src/Dagon.sol)

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

