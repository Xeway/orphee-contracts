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
    constructor(string memory _email, bytes32 _password) {
        wallet.email = _email;
        wallet.password = _password;
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
        require(_tokenAmount > 0, "Insufficient funds.");

        bool transferTokens = IERC20(_tokenAddress).transferFrom(msg.sender, address(this), _tokenAmount);
        require(transferTokens, "Tokens transfer failed.");

        tokenFunds[_tokenAddress] += _tokenAmount;
    }

    /// @notice Send ETH from the wallet to another address
    /// @param _to recipient's address
    /// @param _amount amount to be sent to _to
    /// @param _password wallet's password required to be able to call that function
    function sendFunds(address payable _to, uint _amount, bytes32 _password) public nonReentrant verify(_to, _amount, _password) {
        require(_amount <= address(this).balance && _amount <= wallet.funds, "Insufficient funds.");

        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transaction failed.");

        wallet.funds -= _amount;
    }

    /// @notice Send any token from the wallet to another address
    /// @param _to recipient's address
    /// @param _tokenAddress address of the token to be sent
    /// @param _tokenAmount amount of token to be sent
    /// @param _password wallet's password required to be able to call that function
    function sendTokenFunds(address _to, address _tokenAddress, uint _tokenAmount, bytes32 _password) public verify(_to, _tokenAmount, _password) {
        uint tFunds = tokenFunds[_tokenAddress];
        require(_tokenAmount <= IERC20(_tokenAddress).balanceOf(address(this)) && _tokenAmount <= tFunds, "Insufficient token funds.");

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
    ) public nonReentrant verify(_to, _amount, _password) returns (bytes memory) {
        require(_amount <= address(this).balance && _amount <= wallet.funds, "Insufficient funds.");
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

    modifier verify(address _to, uint _amount, bytes32 _password) {
        require(_amount > 0, "Amount too low.");

        require(_to != address(0), "Invalid recipient.");

        Wallet memory m_wallet = wallet;
        require(keccak256(abi.encodePacked(_password)) == keccak256(abi.encodePacked(m_wallet.password)), "Incorrect password.");

        _;
    }

}
