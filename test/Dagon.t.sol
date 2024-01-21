// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "@forge/Test.sol";

import "@solady/test/utils/mocks/MockERC20.sol";
import "@solady/test/utils/mocks/MockERC721.sol";
import "@solady/test/utils/mocks/MockERC1155.sol";
import "@solady/test/utils/mocks/MockERC6909.sol";

import {LibClone} from "@solady/src/utils/LibClone.sol";
import {Account as NaniAccount} from "@nani/Account.sol";

import {IAuth, Dagon} from "../src/Dagon.sol";

contract DagonTest is Test {
    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal chuck;
    uint256 internal chuckPk;
    address internal dave;
    uint256 internal davePk;
    address internal ed;
    uint256 internal edPk;
    address internal fargo;
    uint256 internal fargoPk;
    address internal gravy;
    uint256 internal gravyPk;
    address internal holly;
    uint256 internal hollyPk;
    address internal ignis;
    uint256 internal ignisPk;
    address internal jake;
    uint256 internal jakePk;
    address internal kate;
    uint256 internal katePk;
    address internal leo;
    uint256 internal leoPk;
    address internal mia;
    uint256 internal miaPk;
    address internal nora;
    uint256 internal noraPk;
    address internal oscar;
    uint256 internal oscarPk;
    address internal piper;
    uint256 internal piperPk;
    address internal quinn;
    uint256 internal quinnPk;
    address internal rick;
    uint256 internal rickPk;
    address internal sara;
    uint256 internal saraPk;
    address internal tina;
    uint256 internal tinaPk;
    address internal uma;
    uint256 internal umaPk;
    address internal vince;
    uint256 internal vincePk;
    address internal wendy;
    uint256 internal wendyPk;
    address internal xander;
    uint256 internal xanderPk;
    address internal yasmine;
    uint256 internal yasminePk;
    address internal zane;
    uint256 internal zanePk;

    mapping(address => uint256) internal keys;

    address internal erc20;
    address internal erc721;
    address internal erc1155;
    address internal erc6909;

    address internal mockAuth;

    NaniAccount internal account;
    uint256 internal accountId;
    Dagon internal dagon;

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
        (ed, edPk) = makeAddrAndKey("ed");
        keys[ed] = edPk;
        (fargo, fargoPk) = makeAddrAndKey("fargo");
        keys[fargo] = fargoPk;
        (gravy, gravyPk) = makeAddrAndKey("gravy");
        keys[gravy] = gravyPk;
        (holly, hollyPk) = makeAddrAndKey("holly");
        keys[holly] = hollyPk;
        (ignis, ignisPk) = makeAddrAndKey("ignis");
        keys[ignis] = ignisPk;
        (jake, jakePk) = makeAddrAndKey("jake");
        keys[jake] = jakePk;
        (kate, katePk) = makeAddrAndKey("kate");
        keys[kate] = katePk;
        (leo, leoPk) = makeAddrAndKey("leo");
        keys[leo] = leoPk;
        (mia, miaPk) = makeAddrAndKey("mia");
        keys[mia] = miaPk;
        (nora, noraPk) = makeAddrAndKey("nora");
        keys[nora] = noraPk;
        (oscar, oscarPk) = makeAddrAndKey("oscar");
        keys[oscar] = oscarPk;
        (piper, piperPk) = makeAddrAndKey("piper");
        keys[piper] = piperPk;
        (quinn, quinnPk) = makeAddrAndKey("quinn");
        keys[quinn] = quinnPk;
        (rick, rickPk) = makeAddrAndKey("rick");
        keys[rick] = rickPk;
        (sara, saraPk) = makeAddrAndKey("sara");
        keys[sara] = saraPk;
        (tina, tinaPk) = makeAddrAndKey("tina");
        keys[tina] = tinaPk;
        (uma, umaPk) = makeAddrAndKey("uma");
        keys[uma] = umaPk;
        (vince, vincePk) = makeAddrAndKey("vince");
        keys[vince] = vincePk;
        (wendy, wendyPk) = makeAddrAndKey("wendy");
        keys[wendy] = wendyPk;
        (xander, xanderPk) = makeAddrAndKey("xander");
        keys[xander] = xanderPk;
        (yasmine, yasminePk) = makeAddrAndKey("yasmine");
        keys[yasmine] = yasminePk;
        (zane, zanePk) = makeAddrAndKey("zane");
        keys[zane] = zanePk;

        // Etch something onto `_ENTRY_POINT` such that we can deploy the account implementation.
        vm.etch(_ENTRY_POINT, hex"00");
        account = NaniAccount(payable(address(LibClone.deployERC1967(address(new NaniAccount())))));
        account.initialize(alice);

        accountId = uint256(uint160(address(account)));

        dagon = new Dagon();

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
        new Dagon();
    }

    function testNameAndSymbolAndDecimals(uint256 id) public {
        assertEq(dagon.name(id), "");
        assertEq(dagon.symbol(id), "");
        assertEq(dagon.decimals(id), 18);
    }

    function testInstall() public {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](1);
        _owners[0].owner = alice;
        _owners[0].shares = 1;

        Dagon.Settings memory setting;
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        assertEq(account.ownershipHandoverExpiresAt(address(dagon)), block.timestamp + 2 days);
        assertEq(dagon.balanceOf(alice, accountId), 1);

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
        );

        (address setTkn, uint88 setThreshold, Dagon.Standard setStd) =
            dagon.getSettings(address(account));

        assertEq(address(setTkn), address(setting.token));
        assertEq(uint256(setThreshold), uint256(setting.threshold));
        assertEq(uint8(setStd), uint8(setting.standard));

        assertEq(dagon.tokenURI(accountId), "");
        (,,, IAuth authority) = dagon.getMetadata(address(account));
        assertEq(address(authority), address(0));
    }

    function testSetThreshold() public {
        testInstall();
        vm.prank(address(account));
        dagon.mint(alice, 1);
        vm.prank(address(account));
        dagon.setThreshold(2);
        (, uint88 setThreshold,) = dagon.getSettings(address(account));
        assertEq(setThreshold, 2);
    }

    function testSpoofSignatures(bytes calldata spoof) public payable {
        bytes32 hash; // Empty hash.
        assertEq(bytes4(0xffffffff), account.isValidSignature(hash, spoof));
    }

    function testFailInvalidThresholdNull() public {
        testInstall();
        vm.prank(address(account));
        dagon.setThreshold(0);
    }

    function testFailInvalidThresholdExceedsSupply() public {
        testInstall();
        vm.prank(address(account));
        dagon.setThreshold(2);
    }

    function testFailInvalidThresholdExceedsSupply2() public {
        testInstall();
        vm.prank(address(account));
        dagon.mint(alice, 1);
        vm.prank(address(account));
        dagon.setThreshold(3);
        (, uint88 setThreshold,) = dagon.getSettings(address(account));
        assertEq(setThreshold, 3);
    }

    function testSetURI() public {
        testInstall();
        vm.prank(address(account));
        dagon.setURI("TEST");
        assertEq(dagon.tokenURI(accountId), "TEST");
    }

    function testSetToken(address tkn) public {
        Dagon.Standard std = Dagon.Standard.DAGON;
        testInstall();
        vm.prank(address(account));
        dagon.setToken(tkn, std);
        (address setTkn,, Dagon.Standard setStd) = dagon.getSettings(address(account));
        assertEq(address(tkn), address(setTkn));
        assertEq(uint8(std), uint8(setStd));
        std = Dagon.Standard.ERC20;
        vm.prank(address(account));
        dagon.setToken(tkn, std);
        (setTkn,, setStd) = dagon.getSettings(address(account));
        assertEq(address(tkn), address(setTkn));
    }

    function testFailSetTokenInvalidStd(address tkn) public {
        testInstall();
        vm.prank(address(account));
        dagon.setToken(tkn, Dagon.Standard(uint8(5)));
    }

    function testSetAuth(IAuth auth) public {
        testInstall();
        vm.prank(address(account));
        dagon.setAuth(auth);
        (,,, IAuth authority) = dagon.getMetadata(address(account));
        assertEq(address(auth), address(authority));
    }

    function testTransfer(address from, address to, uint88 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(from != address(0) && to != address(0));
        vm.assume(to != 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        assertEq(dagon.balanceOf(from, accountId), amount);
        vm.prank(from);
        dagon.transfer(to, accountId, amount);
        assertEq(dagon.balanceOf(from, accountId), 0);
        assertEq(dagon.balanceOf(to, accountId), amount);
    }

    function testFailTransferOverBalance(address from, address to, uint96 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        vm.prank(from);
        dagon.transfer(to, accountId, amount + 1);
    }

    function testTransferWithAuth(address from, address to, uint96 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        vm.prank(address(account));
        dagon.setAuth(IAuth(mockAuth));
        vm.prank(from);
        dagon.transfer(to, accountId, amount);
    }

    function testFailTransferFromInactiveAuth(address from, address to, uint96 amount) public {
        vm.assume(from != alice && to != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        vm.prank(address(account));
        dagon.setAuth(IAuth(address(4269)));
        vm.prank(from);
        dagon.transfer(to, accountId, amount);
    }

    function testBurn(address from, uint96 amount) public {
        vm.assume(from != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        assertEq(dagon.balanceOf(from, accountId), amount);
        vm.prank(address(account));
        dagon.burn(from, amount);
        assertEq(dagon.balanceOf(from, accountId), 0);
    }

    function testFailBurnOverBalance(address from, uint96 amount) public {
        vm.assume(from != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        assertEq(dagon.balanceOf(from, accountId), amount);
        vm.prank(address(account));
        dagon.burn(from, amount + 1);
    }

    function testFailBurnOverThreshold(address from, uint96 amount) public {
        vm.assume(from != alice);
        vm.assume(amount < type(uint96).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        assertEq(dagon.balanceOf(from, accountId), amount);
        vm.prank(address(account));
        dagon.burn(from, amount);
        vm.expectRevert(Dagon.InvalidSetting.selector);
        dagon.burn(alice, 1);
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

        dagon.vote(address(account), userOpHash, signature);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testUserVoted() public {
        testInstall();
        bytes32 userOpHash = keccak256("OWN");
        NaniAccount.UserOperation memory userOp;
        userOp.signature = "";
        require(userOp.signature.length == 0, "INVALID_LEN");
        userOp.sender = address(account);

        bytes memory signature =
            abi.encodePacked(alice, _sign(alicePk, _toEthSignedMessageHash(userOpHash)));

        dagon.vote(address(account), userOpHash, signature);
        assertEq(
            dagon.voted(alice, _toEthSignedMessageHash(userOpHash)),
            dagon.balanceOf(alice, uint256(uint160(address(account))))
        );
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
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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

    function testIsValidSignatureMany() public payable {
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](9);
        _owners[0].owner = alice;
        _owners[0].shares = 1;
        _owners[1].owner = bob;
        _owners[1].shares = 1;
        _owners[2].owner = chuck;
        _owners[2].shares = 1;
        _owners[3].owner = dave;
        _owners[3].shares = 1;
        _owners[4].owner = ed;
        _owners[4].shares = 1;
        _owners[5].owner = fargo;
        _owners[5].shares = 1;
        _owners[6].owner = gravy;
        _owners[6].shares = 1;
        _owners[7].owner = holly;
        _owners[7].shares = 1;
        _owners[8].owner = ignis;
        _owners[8].shares = 1;

        address[] memory addrs = new address[](9);
        addrs[0] = alice;
        addrs[1] = bob;
        addrs[2] = chuck;
        addrs[3] = dave;
        addrs[4] = ed;
        addrs[5] = fargo;
        addrs[6] = gravy;
        addrs[7] = holly;
        addrs[8] = ignis;

        Dagon.Settings memory setting;
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
            _sign(_getPkByAddr(addrs[2]), signHash),
            addrs[3],
            _sign(_getPkByAddr(addrs[3]), signHash),
            addrs[4],
            _sign(_getPkByAddr(addrs[4]), signHash),
            addrs[5],
            _sign(_getPkByAddr(addrs[5]), signHash),
            addrs[6],
            _sign(_getPkByAddr(addrs[6]), signHash),
            addrs[7],
            _sign(_getPkByAddr(addrs[7]), signHash),
            addrs[8],
            _sign(_getPkByAddr(addrs[8]), signHash)
        );

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testIsValidSignatureVeryMany() public payable {
        // Declare the array of ownership structures
        Dagon.Ownership[] memory _owners = new Dagon.Ownership[](26);
        address[] memory addrs = new address[](26);

        // Initialize the _owners array and the addrs array
        _owners[0].owner = alice;
        addrs[0] = alice;
        _owners[0].shares = 1;
        _owners[1].owner = bob;
        addrs[1] = bob;
        _owners[1].shares = 1;
        _owners[2].owner = chuck;
        addrs[2] = chuck;
        _owners[2].shares = 1;
        _owners[3].owner = dave;
        addrs[3] = dave;
        _owners[3].shares = 1;
        _owners[4].owner = ed;
        addrs[4] = ed;
        _owners[4].shares = 1;
        _owners[5].owner = fargo;
        addrs[5] = fargo;
        _owners[5].shares = 1;
        _owners[6].owner = gravy;
        addrs[6] = gravy;
        _owners[6].shares = 1;
        _owners[7].owner = holly;
        addrs[7] = holly;
        _owners[7].shares = 1;
        _owners[8].owner = ignis;
        addrs[8] = ignis;
        _owners[8].shares = 1;
        _owners[9].owner = jake;
        addrs[9] = jake;
        _owners[9].shares = 1;
        _owners[10].owner = kate;
        addrs[10] = kate;
        _owners[10].shares = 1;
        _owners[11].owner = leo;
        addrs[11] = leo;
        _owners[11].shares = 1;
        _owners[12].owner = mia;
        addrs[12] = mia;
        _owners[12].shares = 1;
        _owners[13].owner = nora;
        addrs[13] = nora;
        _owners[13].shares = 1;
        _owners[14].owner = oscar;
        addrs[14] = oscar;
        _owners[14].shares = 1;
        _owners[15].owner = piper;
        addrs[15] = piper;
        _owners[15].shares = 1;
        _owners[16].owner = quinn;
        addrs[16] = quinn;
        _owners[16].shares = 1;
        _owners[17].owner = rick;
        addrs[17] = rick;
        _owners[17].shares = 1;
        _owners[18].owner = sara;
        addrs[18] = sara;
        _owners[18].shares = 1;
        _owners[19].owner = tina;
        addrs[19] = tina;
        _owners[19].shares = 1;
        _owners[20].owner = uma;
        addrs[20] = uma;
        _owners[20].shares = 1;
        _owners[21].owner = vince;
        addrs[21] = vince;
        _owners[21].shares = 1;
        _owners[22].owner = wendy;
        addrs[22] = wendy;
        _owners[22].shares = 1;
        _owners[23].owner = xander;
        addrs[23] = xander;
        _owners[23].shares = 1;
        _owners[24].owner = yasmine;
        addrs[24] = yasmine;
        _owners[24].shares = 1;
        _owners[25].owner = zane;
        addrs[25] = zane;
        _owners[25].shares = 1;

        // Setup the Dagon settings and metadata
        Dagon.Settings memory setting;
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 1;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        // Execute the Dagon install
        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        // Complete ownership handover
        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
        );

        // Prepare for the signature validation
        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        bytes32 signHash = _toEthSignedMessageHash(userOpHash);

        // Sort the addresses and prepare the signature
        addrs = _sortAddresses(addrs);
        userOp.signature = "";
        for (uint256 i = 0; i < addrs.length; i++) {
            userOp.signature = abi.encodePacked(
                userOp.signature, addrs[i], _sign(_getPkByAddr(addrs[i]), signHash)
            );
        }

        // Validate the user operation
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
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 2;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc20;
        setting.standard = Dagon.Standard.ERC20;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc20;
        setting.standard = Dagon.Standard.ERC20;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc721;
        setting.standard = Dagon.Standard.ERC721;
        setting.threshold = 2;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc721;
        setting.standard = Dagon.Standard.ERC721;
        setting.threshold = 2;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc1155;
        setting.standard = Dagon.Standard.ERC1155;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc1155;
        setting.standard = Dagon.Standard.ERC1155;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon), 0, abi.encodeWithSelector(Dagon.install.selector, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc6909;
        setting.standard = Dagon.Standard.ERC6909;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
        setting.token = erc6909;
        setting.standard = Dagon.Standard.ERC6909;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
        );

        NaniAccount.UserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");
        addrs = _sortAddresses(addrs);
        userOp.signature = abi.encodePacked("");

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    /*function testFailIsValidSignatureOutOfOrder() public payable {
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
        setting.token = address(0);
        setting.standard = Dagon.Standard.DAGON;
        setting.threshold = 40;

        Dagon.Metadata memory meta;
        meta.name = "";
        meta.symbol = "";
        meta.tokenURI = "";
        meta.authority = IAuth(address(0));

        vm.prank(alice);
        account.execute(
            address(dagon),
            0,
            abi.encodeWithSelector(Dagon.install.selector, _owners, setting, meta)
        );

        vm.prank(alice);
        account.execute(
            address(account),
            0,
            abi.encodeWithSelector(account.completeOwnershipHandover.selector, address(dagon))
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
    }*/

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
