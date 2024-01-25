// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.23;

import "@forge/Test.sol";
import "@solady/test/utils/mocks/MockERC20.sol";
import "@solady/test/utils/mocks/MockERC721.sol";

import {IAuth, Dagon} from "../src/Dagon.sol";
import {IAccounts, Summoner} from "../src/Summoner.sol";

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
        IAccounts account = summoner.summon(address(this), 1 ether, false, salt);
        assertEq(DAGON.totalSupply(uint256(uint160(address(account)))), 1 ether);
        assertEq(DAGON.balanceOf(address(this), uint256(uint160(address(account)))), 1 ether);
    }

    function testSummoningForERC20(bytes12 salt) public payable {
        summoner.summonForToken(TOKEN, false, 1 ether, salt);
    }

    function testSummoningForNFT(bytes12 salt) public payable {
        summoner.summonForToken(NFT, true, 999, salt);
    }
}
