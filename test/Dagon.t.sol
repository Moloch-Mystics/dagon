// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

import "@forge/Test.sol";

import "@solady/test/utils/mocks/MockERC20.sol";
import "@solady/test/utils/mocks/MockERC721.sol";
import "@solady/test/utils/mocks/MockERC1155.sol";
import "@solady/test/utils/mocks/MockERC6909.sol";

import {SignatureCheckerLib} from "@solady/src/utils/SignatureCheckerLib.sol";

import {IAuth, Dagon} from "../src/Dagon.sol";

/// @dev The ERC4337 userOp struct.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @dev Simple smart account with ERC4337 functions.
contract SimpleAccount {
    address public owner;

    constructor(address _owner) payable {
        owner = _owner;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256)
        external
        payable
        returns (uint256 validationData)
    {
        if (SignatureCheckerLib.isValidSignatureNowCalldata(owner, userOpHash, userOp.signature)) {
            return 0x00;
        } else {
            return 0x01;
        }
    }

    function execute(address to, uint256 value, bytes calldata data)
        public
        payable
        returns (bytes memory retData)
    {
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        retData = ret;
        assert(ok);
    }

    function transferOwnership(address to) public {
        owner = to;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        returns (bytes4)
    {
        if (SignatureCheckerLib.isValidSignatureNowCalldata(owner, hash, signature)) {
            return this.isValidSignature.selector;
        } else {
            return 0xffffffff;
        }
    }
}

/// @dev Dagon singleton test coverage.
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

    SimpleAccount internal account;
    uint256 internal accountId;
    Dagon internal dagon;

    address internal constant _ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    error InsufficientPermission();

    struct Signature {
        address owner;
        bytes sigData;
    }

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

        account = new SimpleAccount(alice);
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

    function testNameAndSymbolAndDecimals(uint256 id) public view {
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

        assertEq(dagon.balanceOf(alice, accountId), 1);

        vm.prank(alice);
        account.transferOwnership(address(dagon));

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
        vm.assume(amount < type(uint88).max);
        testInstall();
        vm.prank(address(account));
        dagon.mint(from, amount);
        assertEq(dagon.balanceOf(from, accountId), amount);
        vm.prank(from);
        dagon.transfer(to, accountId, amount);
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
        PackedUserOperation memory userOp;

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = alice;
        signature[0].sigData = _sign(alicePk, userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testIsValidSignatureOnchain() public {
        testInstall();
        bytes32 userOpHash = keccak256("OWN");
        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        require(userOp.signature.length == 0, "INVALID_LEN");

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = alice;
        signature[0].sigData = _sign(alicePk, userOpHash);

        bytes memory sig = abi.encode(signature);

        dagon.vote(address(account), userOpHash, sig);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testIsValidSignatureOnchainRaw() public {
        testInstall();
        bytes32 userOpHash = keccak256("OWN");
        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        require(userOp.signature.length == 0, "INVALID_LEN");

        vm.prank(alice);
        dagon.vote(address(account), userOpHash);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testFailIsValidSignatureSpoofed() public {
        testInstall();
        bytes32 userOpHash = keccak256("OWN");
        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        require(userOp.signature.length == 0, "INVALID_LEN");

        dagon.vote(address(account), userOpHash);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    function testUserVoted() public {
        testInstall();
        bytes32 userOpHash = keccak256("OWN");
        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        require(userOp.signature.length == 0, "INVALID_LEN");

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = alice;
        signature[0].sigData = _sign(alicePk, userOpHash);

        bytes memory sig = abi.encode(signature);

        dagon.vote(address(account), userOpHash, sig);
        assertEq(
            dagon.voted(address(account), alice, userOpHash),
            dagon.balanceOf(alice, uint256(uint160(address(account))))
        );
        // Flag and revert on double vote.
        vm.prank(alice);
        vm.expectRevert(InsufficientPermission.selector);
        dagon.vote(address(account), userOpHash);
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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](3);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);
        signature[2].owner = addrs[2];
        signature[2].sigData = _sign(_getPkByAddr(addrs[2]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](2);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 6-of-9, 6 signed.
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
        setting.threshold = 6;

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](6);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);
        signature[2].owner = addrs[2];
        signature[2].sigData = _sign(_getPkByAddr(addrs[2]), userOpHash);
        signature[3].owner = addrs[3];
        signature[3].sigData = _sign(_getPkByAddr(addrs[3]), userOpHash);
        signature[4].owner = addrs[4];
        signature[4].sigData = _sign(_getPkByAddr(addrs[4]), userOpHash);
        signature[5].owner = addrs[5];
        signature[5].sigData = _sign(_getPkByAddr(addrs[5]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](3);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);
        signature[2].owner = addrs[2];
        signature[2].sigData = _sign(_getPkByAddr(addrs[2]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        setting.threshold = 40 ether;

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](3);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);
        signature[2].owner = addrs[2];
        signature[2].sigData = _sign(_getPkByAddr(addrs[2]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    // In 40-of-100, 20 ERC20 units signed. So fail.
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
        setting.threshold = 40 ether;

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](2);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        setting.threshold = 40 ether;

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](3);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);
        signature[2].owner = addrs[2];
        signature[2].sigData = _sign(_getPkByAddr(addrs[2]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        setting.threshold = 40 ether;

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        setting.threshold = 40 ether;

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](3);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);
        signature[1].owner = addrs[1];
        signature[1].sigData = _sign(_getPkByAddr(addrs[1]), userOpHash);
        signature[2].owner = addrs[2];
        signature[2].sigData = _sign(_getPkByAddr(addrs[2]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        setting.threshold = 40 ether;

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        addrs = _sortAddresses(addrs);

        Signature[] memory signature = new Signature[](1);
        signature[0].owner = addrs[0];
        signature[0].sigData = _sign(_getPkByAddr(addrs[0]), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

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
        account.transferOwnership(address(dagon));

        PackedUserOperation memory userOp;
        bytes32 userOpHash = keccak256("OWN");

        Signature[] memory signature = new Signature[](3);
        signature[0].owner = _owners[0].owner;
        signature[0].sigData = _sign(_getPkByAddr(_owners[0].owner), userOpHash);
        signature[1].owner = _owners[1].owner;
        signature[1].sigData = _sign(_getPkByAddr(_owners[1].owner), userOpHash);
        signature[2].owner = _owners[2].owner;
        signature[2].sigData = _sign(_getPkByAddr(_owners[2].owner), userOpHash);

        userOp.signature = abi.encode(signature);
        userOp.sender = address(account);

        vm.prank(_ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0x00);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

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

/// @dev Simple authority contract mock.
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
