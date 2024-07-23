// ᗪᗩGOᑎ 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭 𒀭
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

/// @notice Simple summoner for Dagon (𒀭) group accounts.
/// @custom:version 1.1.1
contract Summoner {
    address internal constant DAGON = 0x000000000000FEb893BB5D63bA33323EdCC237cE;
    IAccounts internal constant FACTORY = IAccounts(0x0000000000009f1E546FC4A8F68eB98031846cb8);

    struct Ownership {
        address owner;
        uint96 shares;
    }

    enum Standard {
        DAGON,
        ERC20,
        ERC721,
        ERC1155,
        ERC6909
    }

    function summon(Ownership[] calldata summoners, uint88 threshold, bool locked, bytes12 salt) public payable returns (IAccounts account) {
        account = IAccounts(FACTORY.createAccount{value: msg.value}(address(this), bytes32(abi.encodePacked(this, salt))));
        for (uint256 i; i != summoners.length; ++i) 
            account.execute(DAGON, 0, abi.encodeWithSignature("mint(address,uint96)", summoners[i].owner, summoners[i].shares));
        if (locked) account.execute(DAGON, 0, abi.encodeWithSignature("setAuth(address)", address(0xdead)));
        account.execute(DAGON, 0, abi.encodeWithSignature("setThreshold(uint88)", threshold));
        account.execute(address(account), 0, abi.encodeWithSignature("transferOwnership(address)", DAGON));
    }

    function summonForToken(address token, Standard standard, uint88 threshold, bytes12 salt) public payable returns (IAccounts account) {
        account = IAccounts(FACTORY.createAccount{value: msg.value}(address(this), bytes32(abi.encodePacked(this, salt))));
        account.execute(DAGON, 0, abi.encodeWithSignature("setToken(address,uint8)", token, standard));
        account.execute(DAGON, 0, abi.encodeWithSignature("setThreshold(uint88)", threshold));
        account.execute(address(account), 0, abi.encodeWithSignature("transferOwnership(address)", DAGON));
    }
}

/// @dev Simple interface for Nani (𒀭) user account creation and setup.
interface IAccounts {
    function createAccount(address, bytes32) external payable returns (address);
    function execute(address, uint256, bytes calldata) external payable returns (bytes memory);
}