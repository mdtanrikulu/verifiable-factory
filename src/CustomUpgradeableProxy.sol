// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CustomUpgradeableProxy {
    address public implementation; // The logic contract (registry implementation)
    address public admin;          // The admin (ProxyAdmin)

    // ### Events ###
    event Upgraded(address indexed newImplementation);

    // Modifier that allows only the admin to call certain functions
    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not the admin");
        _;
    }

    constructor(address _implementation, address _admin) {
        implementation = _implementation;
        admin = _admin;
    }

    /**
     * @dev Function to upgrade the proxy's implementation.
     * Can only be called by the admin (which is the ProxyAdmin contract).
     * Emits an {Upgraded} event.
     */
    function upgradeTo(address newImplementation) public onlyAdmin {
        require(newImplementation != address(0), "New implementation cannot be the zero address");
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Function to upgrade and call a function on the new implementation.
     * This is useful when upgrading and initializing in the same transaction.
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) external payable onlyAdmin {
        upgradeTo(newImplementation); // Upgrade to the new implementation

        // Call the function on the new implementation, using delegatecall
        (bool success, ) = newImplementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    /**
     * @dev Fallback function that delegates calls to the current implementation.
     */
    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "Implementation not set");

        // Delegatecall to the current implementation
        (bool success, ) = impl.delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }

    receive() external payable {}
}
