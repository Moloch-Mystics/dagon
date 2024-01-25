# IAuth
[Git Source](https://github.com/Moloch-Mystics/dagon/blob/3c50a9b175611229baf44017b0ba4f798e0515cb/src/Dagon.sol)

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

