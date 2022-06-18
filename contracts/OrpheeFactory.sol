//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "./OrpheeWallet.sol";

contract OrpheeFactory {

    /// @dev mapping that store email => address of the wallet
    mapping(string => address) public wallets;

    function createWallet(string calldata _email, bytes32 _password) public validEmail(_email) validPassword(_password) returns (address) {
        OrpheeWallet c = new OrpheeWallet(_email, _password);
        wallets[_email] = address(c);

        return address(c);
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
