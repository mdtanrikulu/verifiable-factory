// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockRegistry
 * @dev Simulates a registry implementation for testing
 */
contract MockRegistry {
    mapping(address => bool) public registeredAddresses;
    address public admin;
    uint256 public constant version = 1;

    // ### Events
    event AddressRegistered(address indexed account);
    event AddressUnregistered(address indexed account);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    constructor() {
        admin = msg.sender;
    }

    function register(address account) external {
        require(!registeredAddresses[account], "Address already registered");
        registeredAddresses[account] = true;
        emit AddressRegistered(account);
    }

    function unregister(address account) external {
        require(registeredAddresses[account], "Address not registered");
        registeredAddresses[account] = false;
        emit AddressUnregistered(account);
    }

    function isRegistered(address account) external view returns (bool) {
        return registeredAddresses[account];
    }

    function changeAdmin(address newAdmin) external {
        require(msg.sender == admin, "Only admin can change admin");
        require(newAdmin != address(0), "New admin cannot be zero address");
        emit AdminChanged(admin, newAdmin);
        admin = newAdmin;
    }

    function getRegistryVersion() public pure virtual returns (uint256) {
        return version;
    }

    function initialize(address _admin) external {
        require(admin == address(0), "Already initialized");
        admin = _admin;
    }
}
