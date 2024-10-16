// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VerifiableFactory} from "../src/VerifiableFactory.sol";
import {IEVMVerifier} from "@ensdomains/evm-verifier/IEVMVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

contract VerifiableFactoryTest is Test {
    VerifiableFactory public factory;
    address public deployer;
    IEVMVerifier verifier1;
    IEVMVerifier verifier2;
    IEVMVerifier verifier3;

    function setUp() public {
        deployer = address(this);
        verifier1 = IEVMVerifier(address(0));
        verifier2 = IEVMVerifier(address(0));
        verifier3 = IEVMVerifier(address(0));

        VerifiableFactory.Verifiers[] memory verifiers = new VerifiableFactory.Verifiers[](3);
        verifiers[0] = VerifiableFactory.Verifiers({networkId: 1, verifier: address(verifier1)});
        verifiers[1] = VerifiableFactory.Verifiers({networkId: 42, verifier: address(verifier2)});
        verifiers[2] = VerifiableFactory.Verifiers({networkId: 137, verifier: address(verifier3)});

        factory = new VerifiableFactory(verifiers);
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
    }

    function testUpdateRegistry() public {
        uint256 nonce = 1;
        address proxyAddress = factory.deployProxy(nonce);
        address newRegistryAddress = address(0);

        // Update the registry of the deployed proxy
        factory.updateRegistry(proxyAddress, newRegistryAddress);

        // Retrieve the registry from the proxy to confirm the update
        (bool success, bytes memory result) = proxyAddress.call(abi.encodeWithSignature("registry()"));
        assert(success);
        address updatedRegistryAddress = abi.decode(result, (address));
        assertEq(updatedRegistryAddress, newRegistryAddress);
    }

    function testVerifyContract() public {
        uint256 nonce = 1;
        address proxyAddress = factory.deployProxy(nonce);
        factory.verifyContract(proxyAddress, 1);

        // If no revert, verification passed
        assertTrue(true);
    }
}
