//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract OrpheeWallet is ReentrancyGuard, Ownable {
    struct Wallet {
        bytes32 email;
        bytes32 password;
        uint256 funds;
    }
    Wallet wallet;

    // we don't store tokenFunds inside Wallet because that's a mapping and so the whole struct can't be copied to memory (it's therefore not gas-efficient)
    mapping(address => uint256) tokenFunds;
    // tokenList used to loop over tokenFunds
    address[] tokenList;

    address factoryAddress;

    bytes32 tempHash;
    // used to set a cooldown, otherwise an annoying person could change every second tempHash (with recoverPassword())
    // and the owner couldn't have the time to call createNewPassword()
    uint256 lastRecovery;

    /// @param _owner same owner as the factory contract
    /// @param _email email of the wallet's owner
    /// @param _password password of the wallet's owner (password is hashed off-chain)
    constructor(
        address _owner,
        bytes32 _email,
        bytes32 _password
    ) {
        wallet.email = _email;
        wallet.password = _password;

        factoryAddress = msg.sender;

        lastRecovery = block.timestamp;

        _transferOwnership(_owner);
    }

    /// @notice Add ETH in the wallet
    function addFunds() public payable {
        require(msg.value >= 1 wei, "Insufficient funds.");

        wallet.funds += msg.value;
    }

    /// @notice Add any token in the wallet
    /// @param _tokenAddress address of the token sent by the user
    /// @param _tokenAmount amount of token sent by the user
    function addTokenFunds(address _tokenAddress, uint256 _tokenAmount) public {
        require(_tokenAmount > 0, "Insufficient funds.");

        bool transferTokens = IERC20(_tokenAddress).transferFrom(
            msg.sender,
            address(this),
            _tokenAmount
        );
        require(transferTokens, "Tokens transfer failed.");

        tokenFunds[_tokenAddress] += _tokenAmount;

        address[] memory m_tokenList = tokenList;
        bool tokenAlreadyOwned;

        for (uint256 i = 0; i < m_tokenList.length; ++i) {
            if (m_tokenList[i] == _tokenAddress) {
                tokenAlreadyOwned = true;
                break;
            }
        }

        if (!tokenAlreadyOwned) {
            tokenList.push(_tokenAddress);
        }
    }

    /// @notice Send ETH from the wallet to another address
    /// @param _to recipient's address
    /// @param _amount amount to be sent to _to
    /// @param _password wallet's password required to be able to call that function
    function sendFunds(
        address payable _to,
        uint256 _amount,
        bytes32 _password
    ) public nonReentrant verify(_to, _amount, _password) {
        require(
            _amount <= address(this).balance && _amount <= wallet.funds,
            "Insufficient funds."
        );

        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transaction failed.");

        wallet.funds -= _amount;
    }

    /// @notice Send any token from the wallet to another address
    /// @param _to recipient's address
    /// @param _tokenAddress address of the token to be sent
    /// @param _tokenAmount amount of token to be sent
    /// @param _password wallet's password required to be able to call that function
    function sendTokenFunds(
        address _to,
        address _tokenAddress,
        uint256 _tokenAmount,
        bytes32 _password
    ) public verify(_to, _tokenAmount, _password) {
        uint256 tFunds = tokenFunds[_tokenAddress];
        require(
            _tokenAmount <= IERC20(_tokenAddress).balanceOf(address(this)) &&
                _tokenAmount <= tFunds,
            "Insufficient token funds."
        );

        bool success = IERC20(_tokenAddress).transfer(_to, _tokenAmount);
        require(success, "Transaction failed.");

        tokenFunds[_tokenAddress] -= _tokenAmount;

        // if the user send all of his tokens
        // we remove this token from tokenList
        if (tFunds == _tokenAmount) {
            address[] memory m_tokenList = tokenList;

            for (uint256 i = 0; i < m_tokenList.length; ++i) {
                if (m_tokenList[i] == _tokenAddress) {
                    // see: https://solidity-by-example.org/array#examples-of-removing-array-element
                    tokenList[i] = tokenList[m_tokenList.length - 1];
                    tokenList.pop();

                    break;
                }
            }
        }
    }

    /// @notice User call use this function to call functions from external contracts
    /// @param _to contract's address to call
    /// @param _params abi.encodeWithSignature(signatureString, arg) computed off-chain
    /// @param _amount amount to send to _to
    /// @param _gas gas amount to use to call the external function (if 0 we don't precise gas)
    /// @param _password wallet's password required to be able to call that function
    /// @return response from function that have been called
    function callFunctionFromAnotherContract(
        address payable _to,
        bytes calldata _params,
        uint256 _amount,
        uint256 _gas,
        bytes32 _password
    )
        public
        nonReentrant
        verify(_to, _amount, _password)
        returns (bytes memory)
    {
        require(
            _amount <= address(this).balance && _amount <= wallet.funds,
            "Insufficient funds."
        );
        require(
            keccak256(_params) != keccak256(bytes("")),
            "Invalid function call."
        );

        bool success;
        bytes memory res;

        if (_gas > 0) {
            (success, res) = _to.call{value: _amount, gas: _gas}(_params);
        } else {
            (success, res) = _to.call{value: _amount}(_params);
        }
        require(success, "Transaction failed.");

        return res;
    }

    /// @notice Factory contract call this function when user want to delete this wallet
    /// @param _recipient address that will receive all tokens and ethers from that contract
    /// @param _password wallet's password required to be able to call that function
    /// @dev we call the modifier verify and pass 1 as parameter for _amount to be acceptable for this _amount-related requirement
    function deleteWallet(address _recipient, bytes32 _password)
        public
        onlyFactory
        verify(_recipient, 1, _password)
    {
        address[] memory m_tokenList = tokenList;

        for (uint256 i = 0; i < m_tokenList.length; ++i) {
            uint256 tokenFund = tokenFunds[m_tokenList[i]];

            bool success = IERC20(m_tokenList[i]).transfer(
                _recipient,
                tokenFund
            );
            require(success, "Token transfer failed.");
        }

        selfdestruct(payable(_recipient));
    }

    /// @notice Function to call when owner have his password by wants to change it
    /// @param _newPassword password that will replace the old one
    /// @param _password wallet's password required to be able to call that function
    /// @dev we call the verify modifier but we only want to verify for the password so we bypass the two others arguments
    function changePassword(bytes32 _newPassword, bytes32 _password)
        public
        verify(msg.sender, 1, _password)
    {
        wallet.password = _newPassword;
    }

    /// @notice Store the hash computed off-chain in the smart contract
    /// @param _hash hash computed off-chain
    /// @dev when user will recover his password, the app will generate off-chain a random number.
    /// This number will be hashed, and we will hash the hashed number + the email address together (keccak256(hash_number + email)).
    /// This is the value of _hash
    /// @dev onlyOwner used because otherwise anyone can generate his own hash, so here we're sure it's the system that generates the hash
    function recoverPassword(bytes32 _hash, bytes32 _email)
        public
        onlyOwner
        correctEmail(_email)
    {
        require(
            block.timestamp >= lastRecovery + 5 minutes,
            "Wait 5 minutes before recovering again."
        );

        tempHash = _hash;
        lastRecovery = block.timestamp;
    }

    /// @dev once app called recoverPassword(), it will send an email to the owner and the link that the owner will receive will contain the hashed number generated randomly.
    /// Then, when when user has defined his new password and submitted the form, createNewPassword will be called.
    /// The hashed randomly-generated number is passed as _secret. And if the hash that we stored earlier (with recoverPassword()) is equal to keccak256(hash_number + email)
    /// then this means that the user is the owner of the email because he provided the randomly-generated number only accessible in the email.

    /// @notice Used to set the new password
    /// @param _secret randomly-generated hashed number (see above)
    /// @param _email owner's hashed email
    /// @param _newPassword password that will become the new password of this wallet
    function createNewPassword(
        bytes32 _secret,
        bytes32 _email,
        bytes32 _newPassword
    ) public {
        require(
            tempHash == keccak256(bytes.concat(_email, _secret)),
            "Invalid secret."
        );

        require(
            keccak256(abi.encodePacked(_newPassword)) !=
                keccak256(
                    bytes(
                        "0x0000000000000000000000000000000000000000000000000000000000000000"
                    )
                ),
            "Password cannot be empty hash."
        );

        wallet.password = _newPassword;

        delete tempHash;
    }

    /// @notice Function to call to change owner's address
    /// @param _newOwner address of the new owner
    /// @dev see changeOwner() function in OrpheeFactory.sol for more informations
    function changeOwner(address _newOwner) public onlyFactory {
        _transferOwnership(_newOwner);
    }

    /// @notice Checks the validity of some variables
    /// @param _to address to send funds to
    /// @param _amount amount to give
    /// @param _password wallet's password required to be able to call that function
    modifier verify(
        address _to,
        uint256 _amount,
        bytes32 _password
    ) {
        require(_to != address(0), "Invalid recipient.");

        require(_amount > 0, "Amount too low.");

        require(
            keccak256(abi.encodePacked(_password)) ==
                keccak256(abi.encodePacked(wallet.password)),
            "Incorrect password."
        );

        _;
    }

    /// @notice check that the email send as parameter is equal to the email stored in the wallet
    /// @param _email email to check
    /// @dev in the front-end, the owner's email will be stored in the client's browser, so a malicious user could change this value.
    /// This is unsecure because if he call for instance recoverPassword(), the _hash will be according to its email address, and the _secret key
    /// will be sent to his own email address that he replaced
    modifier correctEmail(bytes32 _email) {
        require(_email == wallet.email, "Invalid email.");

        _;
    }

    /// @notice Verify if the function is called by the contract factory
    modifier onlyFactory() {
        require(factoryAddress == msg.sender, "Forbidden function call.");

        _;
    }
}
