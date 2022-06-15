//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SharedWallet {

    struct Wallet {
        string email;
        string password;
        uint funds;
        mapping(address => uint) tokenFunds;
    }

    Wallet wallet;

    // the password will be hashed off-chain
    constructor(string memory _email, string memory _password) validEmail(_email) validPassword(_password) {
        wallet.email = _email;
        wallet.password = _password;
    }

    // verify if the email contain at least a . and a 1 @
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
    }

    modifier validPassword(string memory _password) {
        bytes memory b = bytes(_password);
        bytes memory nullAddr = bytes("0x0000000000000000000000000000000000000000000000000000000000000000");

        // password's length should be 66 because we don't consider 0x, and 1 hexa letter = 1/2 byte
        require(b.length == 66, "Password must be hashed (length 32).");
        // password should start by 0x, because this is a hash (hexa)
        require(b[0] == 0x30 && b[1] == 0x78, "Password must be hashed (start 0x).");
        // we don't want the password == 0x0000000000000000000000000000000000000000
        require(keccak256(b) != keccak256(nullAddr), "Password cannot be empty hash.");

        _;
    }

    function addFunds() public payable {
        require(msg.value >= 1 wei, "Insufficient funds.");
        
        wallet.funds += msg.value;
    }

    function addTokenFunds(address _tokenAddress, uint _tokenAmount) public {
        bool transferTokens = IERC20(_tokenAddress).transferFrom(msg.sender, address(this), _tokenAmount);
        require(transferTokens, "Tokens transfer failed.");

        wallet.tokenFunds[_tokenAddress] = _tokenAmount;
    }
}
