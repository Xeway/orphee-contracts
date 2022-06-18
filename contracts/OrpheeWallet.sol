//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract OrpheeWallet is ReentrancyGuard {

    struct Wallet {
        string email;
        bytes32 password;
        uint funds;
    }
    // we don't store tokenFunds inside Wallet because that's a mapping and so the whole struct can't be copied to memory (it's therefore not gas-efficient)
    mapping(address => uint) tokenFunds;

    Wallet wallet;

    /// @param _email email of the wallet's owner
    /// @param _password password of the wallet's owner (password is hashed off-chain)
    constructor(string memory _email, bytes32 _password) validEmail(_email) validPassword(_password) {
        wallet.email = _email;
        wallet.password = _password;
    }

    /// @notice Verify if the email is valid (contain at least a . and one @)
    modifier validEmail(string memory _email) {
        bytes memory b = bytes(_email);

        bool containAt;
        bool containDot;
        bool errorEmail;

        for (uint i = 0; i < b.length; ++i) {
            if (b[i] == 0x40 && containAt) {
                errorEmail = true;
                break;
            }
            if (b[i] == 0x40) {
                containAt = true;
                if (containDot) break;
            }

            if (b[i] == 0x2e && !containDot) {
                containDot = true;
                if (containAt) break;
            }
        }

        require(!errorEmail, "Invalid email.");
        require(containAt && containDot, "Email should contain @ and .");

        _;
    }

    /// @notice Verify if the password is not a 0x00000 value
    modifier validPassword(bytes32 _password) {
        bytes memory nullAddr = bytes("0x0000000000000000000000000000000000000000000000000000000000000000");

        // we don't want the password == 0x0000000000000000000000000000000000000000
        require(keccak256(abi.encodePacked(_password)) != keccak256(nullAddr), "Password cannot be empty hash.");

        _;
    }

    /// @notice Add ETH in the wallet
    function addFunds() public payable {
        require(msg.value >= 1 wei, "Insufficient funds.");
        
        wallet.funds += msg.value;
    }

    /// @notice Add any token in the wallet
    /// @param _tokenAddress address of the token sent by the user
    /// @param _tokenAmount amount of token sent by the user
    function addTokenFunds(address _tokenAddress, uint _tokenAmount) public {
        bool transferTokens = IERC20(_tokenAddress).transferFrom(msg.sender, address(this), _tokenAmount);
        require(transferTokens, "Tokens transfer failed.");

        tokenFunds[_tokenAddress] += _tokenAmount;
    }

    /// @notice Send ETH from the wallet to another address
    /// @param _to recipient's address
    /// @param _amount amount to be sent to _to
    /// @param _password wallet's password required to be able to call that function
    function sendFunds(address payable _to, uint _amount, bytes32 _password) public nonReentrant {
        Wallet memory m_wallet = wallet;
        require(keccak256(abi.encodePacked(_password)) == keccak256(abi.encodePacked(m_wallet.password)), "Incorrect password.");
        require(_amount >= 1 wei, "Amount too low.");
        require(_amount <= address(this).balance && _amount <= wallet.funds, "Insufficient funds.");
        require(_to != address(0), "Invalid recipient.");

        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transaction failed.");

        wallet.funds -= _amount;
    }

    /// @notice Send any token from the wallet to another address
    /// @param _to recipient's address
    /// @param _tokenAddress address of the token to be sent
    /// @param _tokenAmount amount of token to be sent
    /// @param _password wallet's password required to be able to call that function
    function sendTokenFunds(address _to, address _tokenAddress, uint _tokenAmount, bytes32 _password) public {
        Wallet memory m_wallet = wallet;
        require(keccak256(abi.encodePacked(_password)) == keccak256(abi.encodePacked(m_wallet.password)), "Incorrect password.");
        require(_tokenAmount > 0, "Token amount too low.");
        uint tFunds = tokenFunds[_tokenAddress];
        require(_tokenAmount <= IERC20(_tokenAddress).balanceOf(address(this)) && _tokenAmount <= tFunds, "Insufficient token funds.");
        require(_to != address(0), "Invalid recipient.");

        bool success = IERC20(_tokenAddress).transfer(_to, _tokenAmount);
        require(success, "Transaction failed.");

        tokenFunds[_tokenAddress] -= _tokenAmount;
    }

    /// @notice User call use this function to call functions from external contracts
    /// @param _to contract's address to call
    /// @param _params abi.encodeWithSignature(signatureString, arg) computed off-chain
    /// @param _amount amount to send to _to
    /// @param _gas gas amount to use to call the external function (if 0 we don't precise gas)
    /// @param _password wallet's password required to be able to call that function
    function callFunctionFromAnotherContract(
        address payable _to,
        bytes calldata _params,
        uint _amount,
        uint _gas,
        bytes32 _password
    ) public nonReentrant returns (bytes memory) {
        Wallet memory m_wallet = wallet;
        require(keccak256(abi.encodePacked(_password)) == keccak256(abi.encodePacked(m_wallet.password)), "Incorrect password.");
        require(_amount >= 1 wei, "Amount too low.");
        require(_amount <= address(this).balance && _amount <= wallet.funds, "Insufficient funds.");
        require(_to != address(0), "Invalid recipient.");
        require(keccak256(_params) != keccak256(bytes("")), "Invalid function call.");

        bool success;
        bytes memory res;

        if (_gas > 0) {
            (success, res) = _to.call{value: _amount, gas: _gas}(
                _params
            );
        } else {
            (success, res) = _to.call{value: _amount}(
                _params
            );
        }
        require(success, "Transaction failed.");

        return res;
    }

}
