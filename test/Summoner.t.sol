// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.23;

import "@forge/Test.sol";
import "@solady/test/utils/mocks/MockERC20.sol";
import "@solady/test/utils/mocks/MockERC721.sol";

import {IAuth, Dagon} from "../src/Dagon.sol";
import {IAccounts, Summoner} from "../src/Summoner.sol";

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

contract SummonerTest is Test {
    Dagon internal constant DAGON = Dagon(0x0000000000001D4B1320bB3c47380a3D1C3A1A0C);
    address internal constant FACTORY = 0x000000000000dD366cc2E4432bB998e41DFD47C7;
    address internal constant TOKEN = 0x6B3595068778DD592e39A122f4f5a5cF09C90fE2;
    address internal constant NFT = 0x5Af0D9827E0c53E4799BB226655A1de152A425a5;

    Summoner internal summoner;

    function setUp() public payable {
        vm.createSelectFork(vm.rpcUrl("main")); // Ethereum mainnet fork.
        summoner = new Summoner();
    }

    function testSummoning(bytes12 salt) public payable {
        Summoner.Ownership[] memory summoners = new Summoner.Ownership[](1);
        summoners[0].owner = address(1);
        summoners[0].shares = 1 ether;
        summoner.summon(summoners, 1 ether, false, salt);
    }

    function testSummoningForERC20(bytes12 salt) public payable {
        summoner.summonForToken(TOKEN, Summoner.Standard.ERC20, 1 ether, salt);
    }

    function testSummoningForERC721(bytes12 salt) public payable {
        summoner.summonForToken(NFT, Summoner.Standard.ERC721, 999, salt);
    }

    function testSummoningForERC1155(bytes12 salt) public payable {
        summoner.summonForToken(address(1), Summoner.Standard.ERC1155, 999, salt);
    }

    function testSummoningForERC6909(bytes12 salt) public payable {
        summoner.summonForToken(address(1), Summoner.Standard.ERC6909, 999, salt);
    }
}
