//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SharedWallet {

    struct Wallet {
        string password;
        uint funds;
        mapping(address => uint) tokenFunds;
    }

    Wallet wallet;

    // the password will be hashed off-chain
    constructor(string memory _password) validPassword(_password) {
        wallet.password = _password;
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

    function createWallet(address[] calldata _newOwners) public payable {
        ++walletId;
        // gas efficiency purposes
        uint m_walletId = walletId;

        ownersToWalletIds[msg.sender].push(m_walletId);
        wallets[m_walletId].owners.push(msg.sender);

        // user that created a brand new wallet can decide to directly add owners
        if (_newOwners.length > 0) {
            addOwners(m_walletId, _newOwners);
        }

        if (msg.value >= 1 wei) {
            addFunds(m_walletId);
        }
    }

    function addOwners(uint _walletId, address[] calldata _newOwners) public {
        uint m_walletId = walletId;
        require(_walletId <= m_walletId, "This wallet doesn't exist.");

        bool callerIsOwner;
        address[] memory m_walletOwners = wallets[_walletId].owners;

        for (uint j = 0; j < m_walletOwners.length; ++j) {
            if (m_walletOwners[j] == msg.sender) {
                callerIsOwner = true;
                break;
            }
        }
        require(callerIsOwner, "Caller is not an owner of this wallet.");

        for (uint i = 0; i < _newOwners.length; ++i) {
            ownersToWalletIds[_newOwners[i]].push(_walletId);
            wallets[_walletId].owners.push(_newOwners[i]);
        }
    }

    function addFunds(uint _walletId) public payable {
        require(msg.value >= 1 wei, "Insufficient funds.");
        
        wallets[_walletId].funds += msg.value;
    }

    function addTokenFunds(uint _walletId, address _tokenAddress, uint _tokenAmount) public {
        bool transferTokens = IERC20(_tokenAddress).transferFrom(msg.sender, address(this), _tokenAmount);
        require(transferTokens, "Tokens transfer failed.");

        wallets[_walletId].tokenFunds[_tokenAddress] = _tokenAmount;
    }
}
