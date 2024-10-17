// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockRegistry {
    uint256 public nonce;      // Slot 0
    address public registry;   // Slot 1
    address public admin;      // Slot 2

    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not the admin");
        _;
    }

    // Initialize function
    function initialize(uint256 _nonce, address _admin) external {
        require(nonce == 0, "Already initialized");
        nonce = _nonce;
        admin = _admin;
    }

    // Function to update the registry address
    function updateRegistry(address newRegistry) external onlyAdmin {
        registry = newRegistry;
    }
}
