// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./chainlink-dev/shared/interfaces/IVRFCoordinatorV2Plus.sol";
import "./chainlink-dev/shared/access/ConfirmedOwner.sol";
import "./chainlink-dev/dev/libraries/VRFV2PlusClient.sol";
import "./chainlink-dev/dev/VRFConsumerBaseV2Plus.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol"; // Import IERC20

contract BettingContract is VRFConsumerBaseV2Plus {
    uint256 public s_subscriptionId; // Subscription ID for Chainlink VRF
    bytes32 public keyHash;          // VRF Key Hash
    uint256 public fee;              // Fee for VRF (in LINK)
    uint256 public betAmount = 0.001 ether; // Fixed bet amount in ETH
    uint256 public rewardAmount = 0.002 ether; // Reward amount in ETH
    mapping(uint256 => address) private requestIdToUser; // Maps request ID to user address

    IERC20 public LINKTOKEN; // LINK token interface

    event BetResult(address indexed user, bool won, uint256 amountWon);

constructor(
    address _vrfCoordinator,
    address _linkToken,
    bytes32 _keyHash,
    uint256 _fee,
    address _owner,
    uint256 _subscriptionId // Add this parameter
) VRFConsumerBaseV2Plus(_vrfCoordinator, _owner) {
    LINKTOKEN = IERC20(_linkToken);
    keyHash = _keyHash;
    fee = _fee;
    s_subscriptionId = _subscriptionId; // Assign the value
}

    function placeBet() external payable {
        require(msg.value == betAmount, "Send exactly 0.001 ETH to place a bet.");

        // Request randomness
        uint256 requestId = s_vrfCoordinator.requestRandomWords(
            keyHash,
            uint64(s_subscriptionId),
            3, // Minimum request confirmations
            300000, // Callback gas limit
            1 // Number of random words
        );

        requestIdToUser[requestId] = msg.sender;
    }

    function fulfillRandomWords(
        uint256 requestId,
        uint256[] calldata randomWords
    ) internal override {
        address user = requestIdToUser[requestId];
        delete requestIdToUser[requestId];

        uint256 randomResult = randomWords[0];
        bool won = (randomResult % 100) > 51;

        if (won) {
            payable(user).transfer(rewardAmount);
            emit BetResult(user, true, rewardAmount);
        } else {
            emit BetResult(user, false, 0);
        }
    }

    function withdrawFunds(uint256 amount) external onlyOwnerOrCoordinator {
        payable(contractOwner).transfer(amount);
    }

    function acceptLink(uint256 amount) external onlyOwnerOrCoordinator {
        require(
            LINKTOKEN.transferFrom(msg.sender, address(this), amount),
            "Failed to transfer LINK"
        );
    }
}
