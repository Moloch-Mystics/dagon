// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.23;

import "@forge/Test.sol";

import {MockDagon} from "./utils/mocks/MockDagon.sol";

contract DagonScalesTest is Test {
    MockDagon internal dagon;

    function setUp() public payable {
        dagon = new MockDagon();
    }

    function testIsValidSignatureALOT() public payable {
        bytes memory packedSigs; // Build packed sigs.
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i = 1;
        unchecked {
            for (i; i < 1774; ++i) {
                (v, r, s) = vm.sign(i, bytes32(0));
                packedSigs = abi.encodePacked(packedSigs, vm.addr(i), r, s, v);
            }
        }
        assertEq(dagon.isValidSignature.selector, dagon.isValidSignature(bytes32(0), packedSigs));
    }
}
