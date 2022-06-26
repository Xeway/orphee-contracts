//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

import "./OrpheeWallet.sol";

contract OrpheeFactory is Ownable {

    /// @dev mapping that store email => address of the wallet
    mapping(bytes32 => OrpheeWallet) public wallets;

    /// @dev used to iterate over all wallets
    address[] walletAddresses;

    struct Temp {
        bytes32 tempHash;
        uint lastRecovery;
    }

    mapping(bytes32 => Temp) public temp;

    /// @notice Function to call when user create a brand new wallet
    /// @param _hash hash that represents keccak256([hashed randomly-generated number] + email)
    /// @param _email email to provide to "sign up". This email is used a kind of ID
    /// @dev for more explanation, see OrpheeWallet.sol => recoverPassword()
    /// @dev onlyOwner used because otherwise anyone can generate his own hash, so here we're sure it's the system that generates the hash
    function createWallet(bytes32 _hash, string calldata _email) public onlyOwner validEmail(_email) {
        // better to store bytes32 compared to a string
        // we don't compute the hash off-chain because we first have to verify the email is valid
        bytes32 hashedEmail = keccak256(bytes(_email));

        require(block.timestamp >= temp[hashedEmail].lastRecovery + 5 minutes, "Wait 5 minutes before waiting for the email confirmation again.");

        temp[hashedEmail].tempHash = _hash;
        temp[hashedEmail].lastRecovery = block.timestamp;
    }

    /// @notice Function to call when the user received the confirmation email in order to activate his wallet
    /// @param _secret [hashed randomly-generated number] (see above)
    /// @param _email email to provide to "sign up". This email is used a kind of ID
    /// @param _password password of the wallet's owner (password is hashed off-chain)
    /// @dev no need to call validEmail because we already have done the verification with createWallet, and then if the email is incorrect the hash will be different
    function confirmWalletCreation(bytes32 _secret, bytes32 _email, bytes32 _password) public validPassword(_password) returns (address) {
        require(temp[_email].tempHash == keccak256(bytes.concat(_email, _secret)), "Invalid secret.");
        
        require(address(wallets[_email]) == address(0), "Wallet already exists for this email.");
        
        OrpheeWallet c = new OrpheeWallet(owner(), _email, _password);
        wallets[_email] = c;

        walletAddresses.push(address(c));

        return address(c);
    }

    /// @notice Function to call when user delete his wallet
    /// @param _recipient address that will receive all funds from the contract (ethers and tokens)
    /// @param _email user's email used as a kind of "ID"
    /// @param _password user's password to verify if the caller is really the owner
    function deleteWallet(address _recipient, bytes32 _email, bytes32 _password) public {
        address m_wallet = address(wallets[_email]);
        require(m_wallet != address(0), "Wallet doesn't exists for this email.");

        OrpheeWallet(m_wallet).deleteWallet(_recipient, _password);
        
        delete wallets[_email];

        // we remove from walletAddresses that address of this wallet
        address[] memory m_walletAddresses = walletAddresses;
        for (uint i = 0; i < m_walletAddresses.length; ++i) {
            if (m_walletAddresses[i] == m_wallet) {
                // see: https://solidity-by-example.org/array#examples-of-removing-array-element
                walletAddresses[i] = walletAddresses[m_walletAddresses.length - 1];
                walletAddresses.pop();

                break;
            }
        }
    }

    /// @notice Function to call when contract's owner change owner's address
    /// @param _newOwner address of the new owner
    /// @dev with the help of the loop, we also change the owner's address of all users' wallets
    function changeOwner(address _newOwner) public onlyOwner {
        transferOwnership(_newOwner);

        address[] memory m_walletAddresses = walletAddresses;
        for (uint i = 0; i < m_walletAddresses.length; ++i) {
            OrpheeWallet(m_walletAddresses[i]).changeOwner(_newOwner);
        }
    }

    /// @notice Verify if the email is valid (contain at least a . and one @)
    modifier validEmail(string calldata _email) {
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

}
