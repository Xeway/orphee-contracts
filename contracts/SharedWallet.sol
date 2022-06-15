//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SharedWallet {

    struct Wallet {
        address[] owners;
        uint funds;
        mapping(address => uint) tokenFunds;
    }

    uint public walletId;
    mapping(address => uint[]) public ownersToWalletIds;
    mapping(uint => Wallet) public wallets;

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
