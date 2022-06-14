//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

contract SharedWallet {

    struct Wallet {
        address[] owners;
        uint funds;
    }

    uint public walletId;
    mapping(address => uint[]) public ownersToWalletIds;
    mapping(uint => Wallet) public wallets;

    function createWallet() public {
        ++walletId;
        // gas efficiency purposes
        uint m_walletId = walletId;

        ownersToWalletIds[msg.sender].push(m_walletId);
        wallets[m_walletId].owners.push(msg.sender);
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
        require(msg.value >= 1 wei, "Insufficient funds");
        
        wallets[_walletId].funds += msg.value;
    }
}
