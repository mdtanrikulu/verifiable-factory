// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RegistryProxy {
    uint256 public nonce; // slot 0
    address public registry; // slot 1
    address public admin; // slot 2

    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not the admin");
        _;
    }

    function initialize(uint256 _nonce, address _admin) external {
        require(nonce == 0, "Already initialized");
        nonce = _nonce;
        admin = _admin;  // set the admin (ProxyAdmin contract address)
    }

    function updateRegistry(address newRegistry) external onlyAdmin {
        registry = newRegistry;
    }
}