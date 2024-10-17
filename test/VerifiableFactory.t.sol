// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VerifiableFactory} from "../src/VerifiableFactory.sol";
import {IEVMVerifier} from "@ensdomains/evm-verifier/IEVMVerifier.sol";
import {MockRegistry} from "../src/mock/MockRegistry.sol"; // Ensure this points to your MockRegistry contract
import {CustomUpgradeableProxy} from "../src/CustomUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

contract VerifiableFactoryTest is Test {
    VerifiableFactory public factory;
    ProxyAdmin public proxyAdmin;
    address public deployer;
    IEVMVerifier verifier1;
    IEVMVerifier verifier2;
    IEVMVerifier verifier3;

    function setUp() public {
        deployer = address(this);
        verifier1 = IEVMVerifier(address(0));
        verifier2 = IEVMVerifier(address(0));
        verifier3 = IEVMVerifier(address(0));

        VerifiableFactory.Verifiers[] memory verifiers;
        verifiers[0] = VerifiableFactory.Verifiers({networkId: 1, verifier: address(verifier1)});
        verifiers[1] = VerifiableFactory.Verifiers({networkId: 42, verifier: address(verifier2)});
        verifiers[2] = VerifiableFactory.Verifiers({networkId: 137, verifier: address(verifier3)});

        factory = new VerifiableFactory(verifiers);
        proxyAdmin = new ProxyAdmin(address(factory));  // Initialize the ProxyAdmin with the factory address
    }

    function testFactoryDeployment() public view {
        assert(address(factory) != address(0));
    }

    function testVerifierMapping() public view {
        // Check if verifier addresses are correctly set
        assertEq(address(factory.verifiers(1)), address(verifier1));
        assertEq(address(factory.verifiers(42)), address(verifier2));
        assertEq(address(factory.verifiers(137)), address(verifier3));
    }

    function testDeployProxy() public {
        uint256 nonce = 1;
        address proxyAddress = factory.deployProxy(nonce);

        // Check if proxy was deployed
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(proxyAddress)
        }
        assert(codeSize > 0);
        emit log_named_address("Deployed Proxy Address", proxyAddress);

        // Check if proxy was initialized properly with nonce and proxyAdmin
        (bool success, bytes memory result) = proxyAddress.call(abi.encodeWithSignature("nonce()"));
        assert(success);
        uint256 deployedNonce = abi.decode(result, (uint256));
        assertEq(deployedNonce, nonce);
    }

    function testUpdateRegistry() public {
        uint256 nonce = 1;
        address proxyAddress = factory.deployProxy(nonce);
        address newRegistryAddress = address(0xBEEF);

        // Update the registry of the deployed proxy
        (bool updateSuccess, ) = proxyAddress.call(abi.encodeWithSignature("updateRegistry(address)", newRegistryAddress));
        assert(updateSuccess);

        // Retrieve the registry from the proxy to confirm the update
        (bool retrieveSuccess, bytes memory result) = proxyAddress.call(abi.encodeWithSignature("registry()"));
        assert(retrieveSuccess);
        address updatedRegistryAddress = abi.decode(result, (address));
        assertEq(updatedRegistryAddress, newRegistryAddress);
    }

    function testVerifyContract() public {
        uint256 nonce = 1;
        address proxyAddress = factory.deployProxy(nonce);
        factory.verifyContract(1, proxyAddress);

        // If no revert, verification passed
        assertTrue(true);
    }

    function testUpgradeImplementation() public {
        uint256 nonce = 1;
        address proxyAddress = factory.deployProxy(nonce);

        // Deploy a new MockRegistry as the new implementation
        MockRegistry newRegistryImplementation = new MockRegistry();

        // Upgrade the proxy to point to the new implementation
        factory.upgradeImplementation(proxyAddress, address(newRegistryImplementation));

        // Ensure the proxy's implementation was upgraded by calling a function in the new implementation
        (bool success, bytes memory result) = proxyAddress.call(abi.encodeWithSignature("getRegistryVersion()"));
        assert(success);
        uint256 version = abi.decode(result, (uint256));
        assertEq(version, 1);  // Assuming MockRegistry's version is 1
    }

    function testUpgradeAndCall() public {
        uint256 nonce = 1;
        address proxyAddress = factory.deployProxy(nonce);

        // Deploy a new MockRegistry as the new implementation
        MockRegistry newRegistryImplementation = new MockRegistry();

        // ABI encode data for initializing the new implementation with a specific nonce and registry
        bytes memory data = abi.encodeWithSignature("initialize(uint256,address)", 2, address(proxyAdmin));

        // Upgrade and initialize the new implementation
        factory.upgradeImplementation(proxyAddress, address(newRegistryImplementation));

        // Check if the new implementation was initialized correctly
        (bool success, bytes memory result) = proxyAddress.call(abi.encodeWithSignature("nonce()"));
        assert(success);
        uint256 newNonce = abi.decode(result, (uint256));
        assertEq(newNonce, 2);
    }
}
