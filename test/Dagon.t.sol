// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "@forge/Test.sol";
import "@solady/test/utils/mocks/MockERC20.sol";
import "@solady/test/utils/mocks/MockERC721.sol";
import "@solady/test/utils/mocks/MockERC1155.sol";
import "@solady/test/utils/mocks/MockERC6909.sol";
import {LibClone} from "@solady/src/utils/LibClone.sol";

import {Account as NaniAccount} from "@nani/Account.sol";
import {ITokenOwner, IAuth, Dagon} from "../src/Dagon.sol";

contract MockERC721TotalSupply is MockERC721 {
    uint256 public totalSupply;

    constructor() payable {}

    function mint(address to, uint256 id) public virtual override(MockERC721) {
        _mint(to, id);

        unchecked {
            ++totalSupply;
        }
    }
}

contract MockERC1155TotalSupply is MockERC1155 {
    mapping(uint256 => uint256) public totalSupply;

    constructor() payable {}

    function mint(address to, uint256 id, uint256 amount, bytes memory)
        public
        virtual
        override(MockERC1155)
    {
        _mint(to, id, amount, "");

        totalSupply[id] += amount;
    }
}

contract MockERC6909TotalSupply is MockERC6909 {
    mapping(uint256 => uint256) public totalSupply;

    constructor() payable {}

    function mint(address to, uint256 id, uint256 amount)
        public
        payable
        virtual
        override(MockERC6909)
    {
        _mint(to, id, amount);

        totalSupply[id] += amount;
    }
}

contract MockAuth {
    function validateTransfer(address, address, uint256, uint256)
        public
        payable
        returns (uint256)
    {
        return 0;
    }

    function validateCall(address, address, uint256, bytes calldata)
        public
        payable
        returns (uint256)
    {
        return 0;
    }
}

contract DagonTest is Test {
    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal chuck;
    uint256 internal chuckPk;
    address internal dave;
    uint256 internal davePk;

    mapping(address => uint256) internal keys;

    address internal erc20;
    address internal erc721;
    address internal erc1155;
    address internal erc6909;

    address internal mockAuth;

    NaniAccount internal account;
    uint256 internal accountId;
    Dagon internal owners;

    address internal constant _ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    function setUp() public payable {
        (alice, alicePk) = makeAddrAndKey("alice");
        keys[alice] = alicePk;
        (bob, bobPk) = makeAddrAndKey("bob");
        keys[bob] = bobPk;
        (chuck, chuckPk) = makeAddrAndKey("chuck");
        keys[chuck] = chuckPk;
        (dave, davePk) = makeAddrAndKey("dave");
        keys[dave] = davePk;

        // Etch something onto `_ENTRY_POINT` such that we can deploy the account implementation.
        vm.etch(_ENTRY_POINT, hex"00");
        account = NaniAccount(payable(address(LibClone.deployERC1967(address(new NaniAccount())))));
        account.initialize(alice);

        accountId = uint256(uint160(address(account)));

        owners = new Dagon();

        erc20 = address(new MockERC20("TEST", "TEST", 18));
        MockERC20(erc20).mint(alice, 40 ether);
        MockERC20(erc20).mint(bob, 20 ether);
        MockERC20(erc20).mint(chuck, 20 ether);
        MockERC20(erc20).mint(dave, 20 ether);

        erc721 = address(new MockERC721TotalSupply());
        MockERC721TotalSupply(erc721).mint(alice, 0);
        MockERC721TotalSupply(erc721).mint(bob, 1);
        MockERC721TotalSupply(erc721).mint(chuck, 2);
        MockERC721TotalSupply(erc721).mint(dave, 3);

        erc1155 = address(new MockERC1155TotalSupply());
        MockERC1155TotalSupply(erc1155).mint(alice, accountId, 40 ether, "");
        MockERC1155TotalSupply(erc1155).mint(bob, accountId, 20 ether, "");
        MockERC1155TotalSupply(erc1155).mint(chuck, accountId, 20 ether, "");
        MockERC1155TotalSupply(erc1155).mint(dave, accountId, 20 ether, "");

        erc6909 = address(new MockERC6909TotalSupply());
        MockERC6909TotalSupply(erc6909).mint(alice, accountId, 40 ether);
        MockERC6909TotalSupply(erc6909).mint(bob, accountId, 20 ether);
        MockERC6909TotalSupply(erc6909).mint(chuck, accountId, 20 ether);
        MockERC6909TotalSupply(erc6909).mint(dave, accountId, 20 ether);

        mockAuth = address(new MockAuth());
    }

    function testDeploy() public {
        owners = new Dagon();
    }

    function testNameAndSymbolAndDecimals(uint256 id) public {
        assertEq(owners.name(id), "");
        assertEq(owners.symbol(id), "");
        assertEq(owners.decimals(id), 18);
    }

    function testInstall() public {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](1);
        _owners[0].owner = alice;
        _owners[0].shares = 1;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(address(0));
        setting.std = Dagon.TokenStandard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        assertEq(account.ownershipHandoverExpiresAt(address(owners)), block.timestamp + 2 days);
        assertEq(owners.balanceOf(alice, accountId), 1);

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        (ITokenOwner setTkn, uint88 setThreshold, Dagon.TokenStandard setStd) =
            owners.getSettings(address(account));

        assertEq(address(setTkn), address(setting.tkn));
        assertEq(uint256(setThreshold), uint256(setting.threshold));
        assertEq(uint8(setStd), uint8(setting.std));

        assertEq(owners.tokenURI(accountId), "");
        (,,, IAuth authority) = owners.getMetadata(address(account));
        assertEq(address(authority), address(0));
    }

    function testSetThreshold() public {
        testInstall();
        vm.prank(address(account));
        owners.mint(alice, 1);
        vm.prank(address(account));
        owners.setThreshold(2);
        (, uint88 setThreshold,) = owners.getSettings(address(account));
        assertEq(setThreshold, 2);
    }

    function testFailInvalidThresholdNull() public {
        testInstall();
        vm.prank(address(account));
        owners.setThreshold(0);
    }

    function testFailInvalidThresholdExceedsSupply() public {
        testInstall();
        vm.prank(address(account));
        owners.setThreshold(2);
    }

    function testFailInvalidThresholdExceedsSupply2() public {
        testInstall();
        vm.prank(address(account));
        owners.mint(alice, 1);
        vm.prank(address(account));
        owners.setThreshold(3);
        (, uint88 setThreshold,) = owners.getSettings(address(account));
        assertEq(setThreshold, 3);
    }

    function testSetURI() public {
        testInstall();
        vm.prank(address(account));
        owners.setURI("TEST");
        assertEq(owners.tokenURI(accountId), "TEST");
    }

    function testSetToken(ITokenOwner tkn) public {
        Dagon.TokenStandard std = Dagon.TokenStandard.DAGON;
        testInstall();
        vm.prank(address(account));
        owners.setToken(tkn, std);
        (ITokenOwner setTkn,, Dagon.TokenStandard setStd) = owners.getSettings(address(account));
        assertEq(address(tkn), address(setTkn));
        assertEq(uint8(std), uint8(setStd));
        std = Dagon.TokenStandard.ERC20;
        vm.prank(address(account));
        owners.setToken(tkn, std);
        (setTkn,, setStd) = owners.getSettings(address(account));
        assertEq(address(tkn), address(setTkn));
    }

    function testFailSetTokenInvalidStd(ITokenOwner tkn) public {
        testInstall();
        vm.prank(address(account));
        owners.setToken(tkn, Dagon.TokenStandard(uint8(5)));
    }

    function testSetAuth(IAuth auth) public {
        testInstall();
        vm.prank(address(account));
        owners.setAuth(auth);
        (,,, IAuth authority) = owners.getMetadata(address(account));
        assertEq(address(auth), address(authority));
    }

    function testTransfer(address from, address to, uint96 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(to != address(0) && to != address(0xff));
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        owners.mint(from, amount);
        assertEq(owners.balanceOf(from, accountId), amount);
        vm.prank(from);
        owners.transfer(to, accountId, amount);
        assertEq(owners.balanceOf(from, accountId), 0);
        assertEq(owners.balanceOf(to, accountId), amount);
    }

    function testFailTransferOverBalance(address from, address to, uint96 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        owners.mint(from, amount);
        vm.prank(from);
        owners.transfer(to, accountId, amount + 1);
    }

    function testTransferWithAuth(address from, address to, uint96 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        owners.mint(from, amount);
        vm.prank(address(account));
        owners.setAuth(IAuth(mockAuth));
        vm.prank(from);
        owners.transfer(to, accountId, amount);
    }

    function testFailTransferFromInactiveAuth(address from, address to, uint96 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        owners.mint(from, amount);
        vm.prank(address(account));
        owners.setAuth(IAuth(address(4269)));
        vm.prank(from);
        owners.transfer(to, accountId, amount);
    }

    function testBurn(address from, uint96 amount) public {
        vm.assume(from != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        owners.mint(from, amount);
        assertEq(owners.balanceOf(from, accountId), amount);
        vm.prank(address(account));
        owners.burn(from, amount);
        assertEq(owners.balanceOf(from, accountId), 0);
    }

    function testFailBurnOverBalance(address from, uint96 amount) public {
        vm.assume(from != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        owners.mint(from, amount);
        assertEq(owners.balanceOf(from, accountId), amount);
        vm.prank(address(account));
        owners.burn(from, amount + 1);
    }

    function testFailBurnOverThreshold(address from, uint96 amount) public {
        vm.assume(from != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        owners.mint(from, amount);
        assertEq(owners.balanceOf(from, accountId), amount);
        vm.prank(address(account));
        owners.burn(from, amount);
        vm.expectRevert(Dagon.InvalidSetting.selector);
        owners.burn(alice, 1);
    }

    function testIsValidSignature() public {
        testInstall();
        bytes32 userOpHash = keccak256("OWN");
        NaniAccount.UserOperation memory userOp;
        userOp.signature =
            abi.encodePacked(alice, _sign(alicePk, _toEthSignedMessageHash(userOpHash)));
        require(userOp.signature.length == 85, "INVALID_LEN");
        userOp.sender = address(account);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testIsValidSignatureOnchain() public {
        testInstall();
        bytes32 userOpHash = keccak256("OWN");
        NaniAccount.UserOperation memory userOp;
        userOp.signature = "";
        require(userOp.signature.length == 0, "INVALID_LEN");
        userOp.sender = address(account);

        bytes memory signature =
            abi.encodePacked(alice, _sign(alicePk, _toEthSignedMessageHash(userOpHash)));

        owners.vote(address(account), userOpHash, signature);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 2-of-3, 3 signed.
    function testIsValidSignature3of3() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](3);
        _owners[0].owner = alice;
        _owners[0].shares = 1;
        _owners[1].owner = bob;
        _owners[1].shares = 1;
        _owners[2].owner = chuck;
        _owners[2].shares = 1;

        address[] memory addrs = new address[](3);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(address(0));
        setting.std = Dagon.TokenStandard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(
            addrs[0],
            _sign(_getPkByAddr(addrs[0]), signHash),
            addrs[1],
            _sign(_getPkByAddr(addrs[1]), signHash),
            addrs[2],
            _sign(_getPkByAddr(addrs[2]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 2-of-3, 2 signed.
    function testIsValidSignature2of3() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](3);
        _owners[0].owner = alice;
        _owners[0].shares = 1;
        _owners[1].owner = bob;
        _owners[1].shares = 1;
        _owners[2].owner = chuck;
        _owners[2].shares = 1;

        address[] memory addrs = new address[](3);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(address(0));
        setting.std = Dagon.TokenStandard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(
            addrs[0],
            _sign(_getPkByAddr(addrs[0]), signHash),
            addrs[1],
            _sign(_getPkByAddr(addrs[1]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 2-of-3, 1 signed. So fail.
    function testFailIsValidSignature2of3ForInsufficientSignatures() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](3);
        _owners[0].owner = alice;
        _owners[0].shares = 1;
        _owners[1].owner = bob;
        _owners[1].shares = 1;
        _owners[2].owner = chuck;
        _owners[2].shares = 1;

        address[] memory addrs = new address[](3);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(address(0));
        setting.std = Dagon.TokenStandard.DAGON;
        setting.threshold = 2;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(addrs[0], _sign(_getPkByAddr(addrs[0]), signHash));

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, at least 40 units signed.
    function testIsValidSignatureWeighted() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(address(0));
        setting.std = Dagon.TokenStandard.DAGON;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(
            addrs[0],
            _sign(_getPkByAddr(addrs[0]), signHash),
            addrs[1],
            _sign(_getPkByAddr(addrs[1]), signHash),
            addrs[2],
            _sign(_getPkByAddr(addrs[2]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, 20 units signed. So fail.
    function testFailIsValidSignatureWeighted() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(address(0));
        setting.std = Dagon.TokenStandard.DAGON;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(addrs[0], _sign(_getPkByAddr(addrs[0]), signHash));

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, at least 40 ERC20 units signed.
    function testIsValidSignatureWeightedERC20() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc20);
        setting.std = Dagon.TokenStandard.ERC20;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(
            addrs[0],
            _sign(_getPkByAddr(addrs[0]), signHash),
            addrs[1],
            _sign(_getPkByAddr(addrs[1]), signHash),
            addrs[2],
            _sign(_getPkByAddr(addrs[2]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, 20 units signed. So fail.
    function testFailIsValidSignatureWeightedERC20() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc20);
        setting.std = Dagon.TokenStandard.ERC20;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(addrs[0], _sign(_getPkByAddr(addrs[2]), signHash));

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 2-of-3, at least 2 ERC721 units signed.
    function testIsValidSignatureWeightedERC721() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](3);
        _owners[0].owner = alice;
        _owners[0].shares = 1;
        _owners[1].owner = bob;
        _owners[1].shares = 1;
        _owners[2].owner = chuck;
        _owners[2].shares = 1;

        address[] memory addrs = new address[](3);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc721);
        setting.std = Dagon.TokenStandard.ERC721;
        setting.threshold = 2;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(
            addrs[0],
            _sign(_getPkByAddr(addrs[0]), signHash),
            addrs[1],
            _sign(_getPkByAddr(addrs[1]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 2-of-3, only 1 ERC721 units signed. So fail.
    function testFailIsValidSignatureWeightedERC721() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](3);
        _owners[0].owner = alice;
        _owners[0].shares = 1;
        _owners[1].owner = bob;
        _owners[1].shares = 1;
        _owners[2].owner = chuck;
        _owners[2].shares = 1;

        address[] memory addrs = new address[](3);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc721);
        setting.std = Dagon.TokenStandard.ERC721;
        setting.threshold = 2;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(addrs[0], _sign(_getPkByAddr(addrs[0]), signHash));

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, at least 40 ERC1155 units signed.
    function testIsValidSignatureWeightedERC1155() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc1155);
        setting.std = Dagon.TokenStandard.ERC1155;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(
            addrs[0],
            _sign(_getPkByAddr(addrs[0]), signHash),
            addrs[1],
            _sign(_getPkByAddr(addrs[1]), signHash),
            addrs[2],
            _sign(_getPkByAddr(addrs[2]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, 20 ERC1155 units signed. So fail.
    function testFailIsValidSignatureWeightedERC1155() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc1155);
        setting.std = Dagon.TokenStandard.ERC1155;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners), 0, abi.encodeWithSelector(owners.install.selector, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(addrs[0], _sign(_getPkByAddr(addrs[0]), signHash));

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, at least 40 ERC6909 units signed.
    function testIsValidSignatureWeightedERC6909() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc6909);
        setting.std = Dagon.TokenStandard.ERC6909;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked(
            addrs[0],
            _sign(_getPkByAddr(addrs[0]), signHash),
            addrs[1],
            _sign(_getPkByAddr(addrs[1]), signHash),
            addrs[2],
            _sign(_getPkByAddr(addrs[2]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, 20 ERC6909 units signed. So fail.
    function testFailIsValidSignatureWeightedERC6909() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(erc6909);
        setting.std = Dagon.TokenStandard.ERC6909;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked("");

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testFailIsValidSignatureOutOfOrder() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](4);
        _owners[0].owner = alice;
        _owners[0].shares = 40;
        _owners[1].owner = bob;
        _owners[1].shares = 20;
        _owners[2].owner = chuck;
        _owners[2].shares = 20;
        _owners[3].owner = dave;
        _owners[3].shares = 20;

        address[] memory addrs = new address[](4);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;

        Dagon.Settings memory setting;
        setting.tkn = ITokenOwner(address(0));
        setting.std = Dagon.TokenStandard.DAGON;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(owners),
            0,
            abi.encodeWithSelector(owners.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(owners))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);
        userOp.signature = abi.encodePacked(
            _owners[0].owner,
            _sign(_getPkByAddr(_owners[0].owner), signHash),
            _owners[1].owner,
            _sign(_getPkByAddr(_owners[1].owner), signHash),
            _owners[2].owner,
            _sign(_getPkByAddr(_owners[2].owner), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function _toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, hash) // Store into scratch space for keccak256.
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32") // 28 bytes.
            result := keccak256(0x04, 0x3c) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
        }
    }

    function _getPkByAddr(address user) internal view returns (uint256) {
        return keys[user];
    }

    function _sign(uint256 pK, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pK, hash);
        return abi.encodePacked(r, s, v);
    }

    function _sortAddresses(address[] memory addresses) internal pure returns (address[] memory) {
        for (uint256 i = 0; i < addresses.length; i++) {
            for (uint256 j = i + 1; j < addresses.length; j++) {
                if (uint160(addresses[i]) > uint160(addresses[j])) {
                    address temp = addresses[i];
                    addresses[i] = addresses[j];
                    addresses[j] = temp;
                }
            }
        }
        return addresses;
    }
}
