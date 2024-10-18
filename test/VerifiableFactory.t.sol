// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VerifiableFactory} from "../src/VerifiableFactory.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

contract VerifiableFactoryTest is Test {
    VerifiableFactory public factory;
    ProxyAdmin public proxyAdmin;
    address public deployer;

    function setUp() public {
        deployer = address(this);

        factory = new VerifiableFactory();
    }

    function testFactoryDeployment() public view {
        assert(address(factory) != address(0));
    }

    function testDeployProxy() public {
        uint256 salt = 1;
        address proxyAddress = factory.deployProxy(address(0), salt);

        // Check if proxy was deployed
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(proxyAddress)
        }
        assert(codeSize > 0);
        emit log_named_address("Deployed Proxy Address", proxyAddress);

        // Check if proxy was initialized properly with salt and proxyAdmin
        (bool success, bytes memory result) = proxyAddress.call(
            abi.encodeWithSignature("salt()")
        );
        assert(success);
        uint256 deployedNonce = abi.decode(result, (uint256));
        assertEq(deployedNonce, salt);
    }

    function testUpdateRegistry() public {
        uint256 salt = 1;
        address proxyAddress = factory.deployProxy(address(0), salt);
        address newRegistryAddress = address(0xBEEF);

        // Update the registry of the deployed proxy
        (bool updateSuccess, ) = proxyAddress.call(
            abi.encodeWithSignature(
                "updateRegistry(address)",
                newRegistryAddress
            )
        );
        assert(updateSuccess);

        // Retrieve the registry from the proxy to confirm the update
        (bool retrieveSuccess, bytes memory result) = proxyAddress.call(
            abi.encodeWithSignature("registry()")
        );
        assert(retrieveSuccess);
        address updatedRegistryAddress = abi.decode(result, (address));
        assertEq(updatedRegistryAddress, newRegistryAddress);
    }

    function testVerifyContract() public {
        uint256 salt = 1;
        address proxyAddress = factory.deployProxy(address(0), salt); // tbd
        factory.verifyContract(proxyAddress);

        // If no revert, verification passed
        assertTrue(true);
    }

    function testUpgradeImplementation() public {
        uint256 salt = 1;
        address proxyAddress = factory.deployProxy(address(0), salt); // tbd

        // Upgrade the proxy to point to the new implementation
        factory.upgradeImplementation(proxyAddress, address(0), ""); //tbd

        // Ensure the proxy's implementation was upgraded by calling a function in the new implementation
        (bool success, bytes memory result) = proxyAddress.call(
            abi.encodeWithSignature("getRegistryVersion()")
        );
        assert(success);
        uint256 version = abi.decode(result, (uint256));
        assertEq(version, 1); // Assuming MockRegistry's version is 1
    }

    function testUpgradeAndCall() public {
        uint256 salt = 1;
        address proxyAddress = factory.deployProxy(address(0), salt);

        // ABI encode data for initializing the new implementation with a specific salt and registry
        bytes memory data = abi.encodeWithSignature(
            "initialize(uint256,address)",
            2,
            address(proxyAdmin)
        );

        // Upgrade and initialize the new implementation
        factory.upgradeImplementation(proxyAddress, address(0), ""); // tbd

        // Check if the new implementation was initialized correctly
        (bool success, bytes memory result) = proxyAddress.call(
            abi.encodeWithSignature("salt()")
        );
        assert(success);
        uint256 newNonce = abi.decode(result, (uint256));
        assertEq(newNonce, 2);
    }
}
