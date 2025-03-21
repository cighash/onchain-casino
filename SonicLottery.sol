// Sources flattened with hardhat v2.22.19 https://hardhat.org

// SPDX-License-Identifier: MIT

// File @openzeppelin/contracts/utils/cryptography/ECDSA.sol@v5.2.0

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.28;

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS
    }

    /**
     * @dev The signature derives the `address(0)`.
     */
    error ECDSAInvalidSignature();

    /**
     * @dev The signature has an invalid length.
     */
    error ECDSAInvalidSignatureLength(uint256 length);

    /**
     * @dev The signature has an S value that is in the upper half order.
     */
    error ECDSAInvalidSignatureS(bytes32 s);

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with `signature` or an error. This will not
     * return address(0) without also returning an error description. Errors are documented using an enum (error type)
     * and a bytes32 providing additional information about the error.
     *
     * If no error is returned, then the address can be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     */
    function tryRecover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly ("memory-safe") {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[ERC-2098 short signatures]
     */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        unchecked {
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            // We do not check for an overflow here since the shift operation results in 0 or 1.
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            return tryRecover(hash, v, r, s);
        }
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, r, vs);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }

        return (signer, RecoverError.NoError, bytes32(0));
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Optionally reverts with the corresponding custom error according to the `error` argument provided.
     */
    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }
}


// File contracts/SonicLottery.sol

// Original license: SPDX_License_Identifier: MIT

pragma solidity ^0.8.28;

using ECDSA for bytes32;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner) {
        _transferOwnership(initialOwner);
    }

    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

abstract contract ReentrancyGuard {
    uint256 private _status;
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    constructor() {
        _status = NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != ENTERED, "ReentrancyGuard: reentrant call");
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }
}

interface IGelatoVRFConsumer {
    event RequestedRandomness(uint256 round, bytes data);
    function fulfillRandomness(uint256 randomness, bytes calldata data) external;
}

abstract contract GelatoVRFConsumerBase is IGelatoVRFConsumer {
    uint256 private constant _PERIOD = 3;
    uint256 private constant _GENESIS = 1692803367;
    bool[] public requestPending;
    mapping(uint256 => bytes32) public requestedHash;

    function _operator() internal view virtual returns (address);

    function _fulfillRandomness(uint256 randomness, uint256 requestId, bytes memory extraData) internal virtual;

    function _requestRandomness(bytes memory extraData) internal returns (uint256 requestId) {
        requestId = requestPending.length;
        requestPending.push();
        requestPending[requestId] = true;
        bytes memory data = abi.encode(requestId, extraData);
        uint256 round = _round();
        requestedHash[requestId] = keccak256(abi.encode(round, data));
        emit RequestedRandomness(round, data);
    }

    function fulfillRandomness(uint256 randomness, bytes calldata dataWithRound) external {
        require(msg.sender == _operator(), "Only Gelato VRF Operator can call");

        (, bytes memory data) = abi.decode(dataWithRound, (uint256, bytes));
        (uint256 requestId, bytes memory extraData) = abi.decode(data, (uint256, bytes));

        require(requestPending[requestId], "Request already fulfilled or missing");

        randomness = uint256(keccak256(abi.encode(randomness, address(this), block.chainid, requestId)));

        _fulfillRandomness(randomness, requestId, extraData);
        requestPending[requestId] = false;
        delete requestedHash[requestId];
    }

    function _round() private view returns (uint256 round) {
        uint256 elapsedFromGenesis = block.timestamp - _GENESIS;
        uint256 currentRound = (elapsedFromGenesis / _PERIOD) + 1;
        round = block.chainid == 1 ? currentRound + 4 : currentRound + 1;
    }
}

contract SonicLottery is Ownable, ReentrancyGuard, GelatoVRFConsumerBase {
    using ECDSA for bytes32;

    uint256 public lastLotteryId;
    mapping(uint256 => address[]) public lotteryTickets;
    mapping(uint256 => address) public lotteryWinners;
    mapping(uint256 => bool) public claimedPrizes;
    uint256 public ticketPrice = 1 ether; // 1 Sonic = 1 ticket

    event LotteryCreated(uint256 indexed lotteryId);
    event TicketPurchased(uint256 indexed lotteryId, address indexed buyer, uint256 ticketCount);
    event WinnerRequested(uint256 indexed lotteryId, uint256 requestId);
    event WinnerPicked(uint256 indexed lotteryId, address indexed winner);
    event PrizeClaimed(uint256 indexed lotteryId, address indexed winner, uint256 amount);

    error WinnerAlreadyExists();
    error NoTickets();
    error InvalidWinner();
    error AlreadyClaimed();

constructor(address _gelatoVRF) Ownable(msg.sender) {
    _createLottery();
}


    modifier onlyActiveLottery(uint256 _lotteryId) {
        require(_lotteryId == lastLotteryId, "Invalid lottery ID");
        _;
    }

    function _createLottery() internal {
        lastLotteryId++;
        emit LotteryCreated(lastLotteryId);
    }

    function buyTicket(uint256 _lotteryId) external payable onlyActiveLottery(_lotteryId) nonReentrant {
        require(msg.value >= ticketPrice, "Minimum 1 Sonic required");

        uint256 ticketCount = msg.value / ticketPrice;
        for (uint256 i = 0; i < ticketCount; i++) {
            lotteryTickets[_lotteryId].push(msg.sender);
        }

        emit TicketPurchased(_lotteryId, msg.sender, ticketCount);
    }

    function pickWinner(uint256 _lotteryId) external onlyOwner onlyActiveLottery(_lotteryId) {
        if (lotteryWinners[_lotteryId] != address(0)) revert WinnerAlreadyExists();
        if (lotteryTickets[_lotteryId].length == 0) revert NoTickets();

        uint256 requestId = _requestRandomness("");
        emit WinnerRequested(_lotteryId, requestId);
    }

    function _fulfillRandomness(uint256 _randomNumber, uint256 requestId, bytes memory extraData) internal override {
        uint256 _lotteryId = lastLotteryId;

        if (lotteryTickets[_lotteryId].length == 0) return;

        uint256 randomIndex = _randomNumber % lotteryTickets[_lotteryId].length;
        address winner = lotteryTickets[_lotteryId][randomIndex];

        lotteryWinners[_lotteryId] = winner;
        emit WinnerPicked(_lotteryId, winner);

        _createLottery();
    }

    function _operator() internal view override returns (address) {
        return owner();
    }

    function claimPrize(uint256 _lotteryId) external nonReentrant {
        if (lotteryWinners[_lotteryId] != msg.sender) revert InvalidWinner();
        if (claimedPrizes[_lotteryId]) revert AlreadyClaimed();

        uint256 prizeAmount = ticketPrice * lotteryTickets[_lotteryId].length;
        claimedPrizes[_lotteryId] = true;
        payable(msg.sender).transfer(prizeAmount);

        emit PrizeClaimed(_lotteryId, msg.sender, prizeAmount);
    }

    function getTickets(uint256 _lotteryId) external view returns (address[] memory) {
        return lotteryTickets[_lotteryId];
    }
}
