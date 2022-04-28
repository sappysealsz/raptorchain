pragma solidity ^0.7.0;
pragma abicoder v2;

//SPDX-License-Identifier: MIT


interface ERC20Interface {
    function totalSupply() external view returns (uint);
    function balanceOf(address tokenOwner) external view returns (uint balance);
    function allowance(address tokenOwner, address spender) external view returns (uint remaining);
    function transfer(address to, uint tokens) external returns (bool success);
    function approve(address spender, uint tokens) external returns (bool success);
    function transferFrom(address from, address to, uint tokens) external returns (bool success);
}

interface BridgeFallbackInterface {
	function bridgeFallBack(bytes32 _hash, bytes memory _data) external;
}


library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

library Math {
	function sum(uint256[] memory numbers) internal pure returns (uint256 _sum) {
		uint256 i = 0;
		while (i < numbers.length) {
			_sum += numbers[i];
			i += 1;
		}
	}
	
	function min(uint256[] memory numbers) internal pure returns (uint256 _min) {
		uint256 i = 0;
		_min = numbers[0];
		while (i < numbers.length) {
			if (_min > numbers[i]) {
				_min = numbers[i];
			}
			i += 1;
		}
	}
	
	function max(uint256[] memory numbers) internal pure returns (uint256 _max) {
		uint256 i = 0;
		_max = numbers[0];
		while (i < numbers.length) {
			if (_max < numbers[i]) {
				_max = numbers[i];
			}
			i += 1;
		}
	}
}

contract CustodyManager {
	using SafeMath for uint256;
	struct Deposit {
		uint256 amount; // deposit value
		address depositor; // address that deposits tokens
		uint256 nonce;
		address token; // or address 0 if you deposit BNB
		bytes data; // data appended to deposit (could be passed to a contract on raptorchain)
		bytes32 hash; // keccak256(abi.encodePacked(amount, depositor, token, blockhash(), data, nonce))
	}
	
	struct Withdrawal {
		uint256 amount; // withdrawal value
		address withdrawer; // address that tokens
		uint256 nonce;
		address token; // withdrawn token
		bytes32 hash;
		bool claimed;
	}
	
	
	address masterContract;
	Deposit[] public __deposits;
	mapping (bytes32 => Deposit) public _deposits;
	
	Withdrawal[] public __withdrawals;
	mapping (bytes32 => Withdrawal) public _withdrawals;
	
	
	uint256 public transferNonce = 0;
	uint256 public totalDeposited;
	address withdrawalsOperator;
	event WithdrawalOperatorChanged(address indexed oldOperator, address indexed newOperator);
	// StakeManager public stakingManager;
	
	// constructor(StakeManager _stakingManager) {
	constructor(address _withdrawalsOperator) {
		masterContract = msg.sender;
		withdrawalsOperator = _withdrawalsOperator;
	}
	
	function changeWithdrawalOperator(address _newOperator) public {
		require(msg.sender == address(withdrawalsOperator), "Only withdrawals operator address can do that :/");
		emit WithdrawalOperatorChanged(withdrawalsOperator, _newOperator);
		withdrawalsOperator = _newOperator;
	}
	
	event Deposited(address indexed user, address indexed token, uint256 amount, uint256 nonce, bytes32 hash);
	event Withdrawn(address indexed user, address indexed token, uint256 amount, uint256 nonce, bytes32 hash);
	
	function deposits(uint256 _index) public view returns (Deposit memory) {
		return __deposits[_index];
	}
	
	function deposits(bytes32 _hash) public view returns (Deposit memory) {
		return _deposits[_hash];
	}

	function withdrawals(uint256 _index) public view returns (Withdrawal memory) {
		return __withdrawals[_index];
	}
	
	function withdrawals(bytes32 _hash) public view returns (Withdrawal memory) {
		return _withdrawals[_hash];
	}

	function _deposit(address token, address user, uint256 amount, bytes memory data) private {
		ERC20Interface _token = ERC20Interface(token);
		uint256 balanceBefore = _token.balanceOf(address(this));
		_token.transferFrom(user, address(this), amount);
		uint256 received = _token.balanceOf(address(this)).sub(balanceBefore);
		
		bytes32 _hash_ = keccak256(abi.encodePacked(received, user, blockhash(block.number-1), data, transferNonce));
		Deposit memory _newDeposit = Deposit({amount: received, depositor: user, nonce: transferNonce, token: token, data: data, hash: _hash_});
		__deposits.push(_newDeposit);
		_deposits[_hash_] = _newDeposit;
		emit Deposited(user, token, received, transferNonce, _hash_);
		transferNonce += 1;
	}
	
	function deposit(address token, uint256 amount, bytes memory data) public {
		_deposit(token, msg.sender, amount, data); // using same function for approveAndCall and "legacy" deposit
		// ERC20Interface _token = ERC20Interface(token);
		// uint256 balanceBefore = _token.balanceOf(address(this));
		// _token.transferFrom(msg.sender, address(this), amount);
		// uint256 received = _token.balanceOf(address(this)).sub(balanceBefore);
		// bytes32 _hash_ = keccak256(abi.encodePacked(received,msg.sender, blockhash(block.number-1), transferNonce));
		// Deposit memory _newDeposit = Deposit({amount: received, depositor: msg.sender, nonce: transferNonce, token: token, hash: _hash_});
		// __deposits.push(_newDeposit);
		// _deposits[_hash_] = _newDeposit;
		// emit Deposited(msg.sender, token, received, transferNonce, _hash_);
		// transferNonce += 1;
	}
	
	function receiveApproval(address spender, uint256 _amount, address token, bytes memory _data) public {
		require(msg.sender == token, "INVALID_TOKEN_ADDRESS");
		_deposit(token, spender, _amount, _data);
	}
	
	function requestWithdrawal(address token, address withdrawer, uint256 amount, uint256 nonce, bytes32 l2Hash) private {
		// bytes32 _hash = keccak256(abi.encodePacked(amount, withdrawer, token, nonce));
		// require(l2Hash == _hash, "HASH_UNMATCHED");
		require(!_withdrawals[l2Hash].claimed, "ALREADY_CLAIMED");
		Withdrawal memory _newWithdrawal = Withdrawal({amount: amount, withdrawer: withdrawer, nonce: nonce, token: token, hash: l2Hash, claimed: true});
		_withdrawals[l2Hash] = _newWithdrawal;
		__withdrawals.push(_newWithdrawal);
		ERC20Interface(token).transfer(withdrawer, amount);
		emit Withdrawn(withdrawer, token, amount, nonce, l2Hash);
	}
	
	function execBridgeCall(bytes memory _data) public {
		require(msg.sender == address(withdrawalsOperator), "Only withdrawals operator address can do that :/");
		bytes32 _hash = keccak256(_data);
		(address token, address withdrawer, uint256 amount, uint256 nonce) = abi.decode(_data, (address, address, uint256, uint256));
		requestWithdrawal(token, withdrawer, amount, nonce, _hash);
	}
	
	function depositsLength() public view returns (uint256) {
		return __deposits.length;
	}
}

contract BeaconChainHandler {
	struct Beacon {
		address miner;
		uint256 nonce;
		bytes[] messages;
		uint256 difficulty;
		bytes32 miningTarget;
		uint256 timestamp;
		bytes32 parent;
		bytes32 proof;
		uint256 height;
		bytes32 son;
		bytes32 parentTxRoot;
		uint8 v;
		bytes32 r;
		bytes32 s;
	}
	// StakeManager public stakingContract;
	address owner;
	Beacon[] public beacons;
	uint256 blockTime = 600;
	address handler;
	
	event CallExecuted(address indexed to, bytes data, bool success);
	event CallDismissed(address indexed to, bytes data, string reason);
	
	modifier onlyOwner {
		require(msg.sender == owner);
		_;
	}
	
	function _chainId() internal pure returns (uint256) {
		uint256 id;
		assembly {
			id := chainid()
		}
		return id;
	}
	
	constructor(Beacon memory _genesisBeacon, address _owner) {
		owner = _owner;
		beacons.push(_genesisBeacon);
		beacons[0].height = 0;
		handler = msg.sender;
	}
	
	function beaconHash(Beacon memory _beacon) public pure returns (bytes32 beaconRoot) {
		bytes32 messagesRoot = keccak256(abi.encode(_beacon.messages));
		bytes32 bRoot = keccak256(abi.encodePacked(_beacon.parent, _beacon.timestamp,  messagesRoot, _beacon.parentTxRoot, _beacon.miner));
		beaconRoot = keccak256(abi.encodePacked(bRoot, _beacon.nonce));
	}
	
	function isBeaconValid(Beacon memory _beacon) public view returns (bool valid, string memory reason) {
		bytes32 _hash = beaconHash(_beacon);
		if (_hash != _beacon.proof) {
			return (false, "UNMATCHED_HASH");
		}
		bytes32 lastBlockHash = beacons[beacons.length-1].proof;
		if (lastBlockHash != _beacon.parent) {
			return (false, "UNMATCHED_PARENT");
		}
		if (_beacon.height != beacons.length) {
			return (false, "UNMATCHED_HEIGHT");
		}
		if ((_beacon.timestamp > block.timestamp) || (_beacon.timestamp < (beacons[beacons.length-1].timestamp + blockTime))) {
			return (false, "UNMATCHED_TIMESTAMP");
		}
		if (ecrecover(_beacon.proof, _beacon.v, _beacon.r, _beacon.s) != _beacon.miner) {
			return (false, "INVALID_SIGNATURE");
		}
		return (true, "VALID_BEACON");
	}
	
	function executeCall(bytes memory message) private {
		handler.call(abi.encodeWithSelector(bytes4(keccak256("routeCall(bytes)")), message));
	}
	
	function extractBeaconMessages(Beacon memory _beacon) public pure returns (bytes[] memory messages, uint256 length) {
		return (_beacon.messages, _beacon.messages.length);
	}
	
	function executeMessages(Beacon memory _beacon) private {
		for (uint256 n = 0; n<_beacon.messages.length; n++) {
			executeCall(_beacon.messages[n]);
			n += 1;
		}
	}
	
	function pushBeacon(Beacon memory _beacon) public onlyOwner {
		(bool _valid, string memory _reason) = isBeaconValid(_beacon);
		require(_valid, _reason);
		beacons.push(_beacon);
		beacons[beacons.length-2].son = _beacon.proof;
		
		executeMessages(_beacon);
		// copyValidatorSet(beacons.length-1, beacons.length);
	}
	
	function chainLength() public view returns (uint256) {
		return beacons.length;
	}
}


contract ChainsImplementationHandler {
	address[] public instances;
	mapping (address => bool) public isInstance;
	mapping (address => address[]) public instancesPerOwner;
	
	BeaconChainHandler.Beacon public genesisBeacon;
	ERC20Interface public stakingToken;
	address owner;
	address officialInstance;
	
	event CallExecuted(address indexed to, bytes data, bool success);
	event CallDismissed(address indexed to, bytes data, string reason);
	
	modifier onlyOwner {
		require(msg.sender == owner);
		_;
	}

	constructor(BeaconChainHandler.Beacon memory _genesisBeacon, ERC20Interface _stakingToken) {
		genesisBeacon = _genesisBeacon;
		stakingToken = _stakingToken;
		owner = tx.origin;
	}

	function _chainId() internal pure returns (uint256) {
		uint256 id;
		assembly {
			id := chainid()
		}
		return id;
	}
	
	function transferOwnership(address _to) public onlyOwner {
		owner = _to;
	}
	
	function setOfficialInstance(address _instance) public onlyOwner{
		officialInstance = _instance;
	}
	
	function getAllInstances() public view returns (address[] memory) {
		return instances;
	}
	
	function createInstance(address instanceOwner) public {
		address newInstance = address(new BeaconChainHandler(genesisBeacon, instanceOwner));
		instances.push(newInstance);
		isInstance[newInstance] = true;
		instancesPerOwner[instanceOwner].push(newInstance);
	}
	
	function routeCall(bytes memory call) public {
		if (msg.sender != officialInstance) {
			return;
		}
		(address recipient, uint256 chainID, bytes memory data) = abi.decode(call, (address, uint256, bytes));
		if (_chainId() == chainID) {
			(bool success, ) = recipient.call(abi.encodeWithSelector(bytes4(keccak256("execBridgeCall(bytes)")), data));
			emit CallExecuted(recipient, data, success);
		}
		else {
			emit CallDismissed(recipient, data, "INVALID_CHAIN_ID");
		}
	}
}

contract MasterContract {
	// StakeManager public staking;
	CustodyManager public custody;
    ChainsImplementationHandler public chainInstances;
	
	// comment used as a reminder, DON'T REMOVE
	// struct Beacon {
		// address miner; // "0x0000000000000000000000000000000000000000"
		// uint256 nonce; // 0
		// bytes[] messages; // ["0x48657920677579732c206a75737420747279696e6720746f20696d706c656d656e742061206b696e64206f6620726170746f7220636861696e2c206665656c206672656520746f20686176652061206c6f6f6b"]
		// uint256 difficulty; // 1
		// bytes32 miningTarget; // bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
		// uint256 timestamp; // 1650271392
		// bytes32 parent; // bytes32(0x496e697469616c697a696e672074686520526170746f72436861696e2e2e2e20)
		// bytes32 proof; // bytes32(0x5115cbb8aab4470dcdb6950eb0e36d5ac7bb3ebb92988c21a5dc35547100a8ef)
		// uint256 height; // 0
		// bytes32 son; // "0x0000000000000000000000000000000000000000000000000000000000000000"
		// bytes32 parentTxRoot; // bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)
		// uint8 v; // 0
		// bytes32 r; // bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)
		// bytes32 s; // bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)
	// }
	
	// BeaconChainHandler.Beacon({miner: address(0), nonce: 0, messages: [bytes("0x48657920677579732c206a75737420747279696e6720746f20696d706c656d656e742061206b696e64206f6620726170746f7220636861696e2c206665656c206672656520746f20686176652061206c6f6f6b")], difficulty: 1, miningTarget: bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff), timestamp: 1650271392, parent: bytes32(0x496e697469616c697a696e672074686520526170746f72436861696e2e2e2e20), proof: bytes32(0x5115cbb8aab4470dcdb6950eb0e36d5ac7bb3ebb92988c21a5dc35547100a8ef), height: 0, son: bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), parentTxRoot: bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), v: 0, r: bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), s: bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)})
	
	
	// calldata to use on deployment
	// GenesisBeacon calldata : ["0x0000000000000000000000000000000000000000",0,["0x48657920677579732c206a75737420747279696e6720746f20696d706c656d656e742061206b696e64206f6620726170746f7220636861696e2c206665656c206672656520746f20686176652061206c6f6f6b"],1,"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",1645457628,"0x496e697469616c697a696e672074686520526170746f72436861696e2e2e2e00","0x7d9e1f415e0084675c211687b1c8dfaee67e53128e325b5fdda9c98d7288aaeb",0,"0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000",0,"0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000"]
	
	constructor(BeaconChainHandler.Beacon memory _genesisBeacon, ERC20Interface stakingToken) {
		// staking = new StakeManager(stakingToken);
		custody = new CustodyManager(msg.sender); // to change after deployment
        chainInstances = new ChainsImplementationHandler(_genesisBeacon, stakingToken);
		// beaconchain = new BeaconChainHandler(_genesisBeacon, staking);
		// staking.setBeaconHandler(beaconchain);
	}
	
}