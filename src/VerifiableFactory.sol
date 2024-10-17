// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EVMFetcher} from "@ensdomains/evm-verifier/EVMFetcher.sol";
import {EVMFetchTarget} from "@ensdomains/evm-verifier/EVMFetchTarget.sol";
import {IEVMVerifier} from "@ensdomains/evm-verifier/IEVMVerifier.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {CustomUpgradeableProxy} from "./CustomUpgradeableProxy.sol";

import {MockRegistry} from "./mock/MockRegistry.sol";

interface IProxy {
    function nonce() external view returns (uint256);

    function registry() external view returns (address);
}

contract VerifiableFactory is EVMFetchTarget {
    using EVMFetcher for EVMFetcher.EVMFetchRequest;

    struct Verifiers {
        uint256 networkId;
        address verifier;
    }

    ProxyAdmin public proxyAdmin;
    uint256 constant PROXY_NONCE_SLOT = 0;
    uint256 constant PROXY_REGISTRY_SLOT = 1;

    mapping(uint256 => IEVMVerifier) public verifiers;

    event ProxyDeployed(address indexed proxyAddress);

    constructor(Verifiers[] memory _verifiers) {
        require(
            _verifiers.length > 0,
            "At least one verifier address must be set"
        );

        for (uint256 i = 0; i < _verifiers.length; i++) {
            verifiers[_verifiers[i].networkId] = IEVMVerifier(
                _verifiers[i].verifier
            );
        }

        proxyAdmin = new ProxyAdmin(address(this));
    }

    /**
     * @dev deploys a new `CustomUpgradeableProxy` contract using a deterministic address derived from
     *      the sender's address and a nonce.
     *
     * The function creates a new proxy contract that is controlled by the factory's `ProxyAdmin`.
     * When the proxy is deployed, it starts by using the `RegistryProxy` contract as its main implementation.
     * During the deployment, the initialize function is called to set up the proxy.
     * The nonce ensures that each user gets a unique proxy, even if the same user deploys multiple proxies.
     *
     * - The function uses a `salt` to create a deterministic address based on `msg.sender` and a provided nonce.
     * - The `initialize` function of the `RegistryProxy` contract is called immediately after deployment to set up
     *   the proxy with the nonce and `ProxyAdmin`.
     * - The proxy is managed by a `ProxyAdmin` contract, ensuring that upgrades and critical functions are restricted to the admin.
     * - A custom event `ProxyDeployed` is emitted to track the deployment of the new proxy.
     *
     * @param nonce A unique number provided by the caller to create a unique proxy address.
     * @return proxy The address of the deployed `CustomUpgradeableProxy` contract.
     */
    function deployProxy(uint256 nonce) external returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));

        MockRegistry registryInstance = new MockRegistry();
        address proxy = address(
            new CustomUpgradeableProxy{salt: salt}(
                address(registryInstance),
                address(proxyAdmin)
            )
        );

        require(isContract(proxy), "Proxy deployment failed");

        MockRegistry(address(proxy)).initialize(nonce, address(proxyAdmin));

        emit ProxyDeployed(proxy);
        return proxy;
    }

    // Function to upgrade the proxy's implementation (only admin can call this)
    function upgradeImplementation(
        address proxyAddress,
        address newImplementation /* bytes memory data */
    ) external {
        require(
            msg.sender == address(proxyAdmin),
            "Only the ProxyAdmin can upgrade"
        );

        // Upgrade the proxy to point to the new implementation
        CustomUpgradeableProxy(payable(proxyAddress)).upgradeTo(
            newImplementation
        );
        // CustomUpgradeableProxy(payable(proxyAddress)).upgradeToAndCall{value: 0}(newImplementation, data);
    }

    /**
     * @dev verifies a proxy contract on a specified network using the EVMGateway.
     *
     * The function starts the process of verifying a specific proxy contract by sending a request
     * to the correct IEVMVerifier for the given network. It then retrieves fixed values from certain
     * storage slots (like the proxy's nonce and registry address) to help with the verification
     *
     * The verification request is sent through the `EVMFetcher` to the gateway, and the result
     * is processed by the `verifyCallback` function upon completion.
     *
     * - The function looks up the correct verifier for the network based on the provided `networkId`.
     * - It retrieves static values from storage slots (`PROXY_NONCE_SLOT` and `PROXY_REGISTRY_SLOT`) to assist in the verification process.
     * - The fetched data is passed to `verifyCallback` for further processing.
     *
     * @param proxy The address of the proxy contract to be verified.
     * @param networkId The ID of the network where the verification will take place.
     */
    // Merged verifyContract method for both same-chain and cross-chain verification
    function verifyContract(
        uint256 networkId, // The target network ID
        address proxy // The proxy contract address
    ) external view {
        if (networkId == block.chainid) {
            // Same-chain verification
            _verifyContractSameChain(proxy);
        } else {
            // Cross-chain verification
            _verifyContractCrossChain(networkId, proxy);
        }
    }

    // Internal method for same-chain verification
    function _verifyContractSameChain(
        address proxy
    ) internal view returns (bool) {
        // directly fetch storage
        uint256 nonce = IProxy(proxy).nonce();
        address registry = IProxy(proxy).registry();

        // reconstruct the address using CREATE2 and the original salt
        bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));

        // use the bytecode of CustomUpgradeableProxy with constructor arguments
        bytes memory bytecode = abi.encodePacked(
            type(CustomUpgradeableProxy).creationCode,
            abi.encode(registry, address(proxyAdmin))
        );

        // Compute the expected proxy address using the salt
        address expectedProxyAddress = Create2.computeAddress(
            salt,
            keccak256(bytecode)
        );

        // Verify if the computed address matches the proxy address
        require(expectedProxyAddress == proxy, "Proxy address mismatch");

        // Verify other storage slots like registry address
        require(registry != address(0), "Invalid registry address");

        return true;
    }

    // Internal method for cross-chain verification (e.g., L1 -> L2)
    function _verifyContractCrossChain(
        uint256 networkId,
        address proxy
    ) internal view {
        IEVMVerifier verifier = verifiers[networkId];
        require(
            address(verifier) != address(0),
            "No verifier set for this network"
        );

        EVMFetcher
            .newFetchRequest(verifier, proxy)
            .getStatic(PROXY_NONCE_SLOT)
            .getStatic(PROXY_REGISTRY_SLOT)
            .fetch(this.verifyCallback.selector, abi.encode(proxy)); // Get the nonce and the registry slot
    }

    /**
     * @dev callback function that processes the response from the EVMGateway after fetching the verification data.
     *
     * This function decodes the fetched data and verifies the correctness of the proxy contract's address by
     * calculating the expected address using a salt derived from the sender's address and the proxy's nonce.
     *
     * - The response data contains the nonce, registry address, and extra data (proxy address) retrieved from both verfiyContract and gateway requests.
     * - The proxy address is reconstructed using the same logic used during deployment to ensure it matches the expected proxy address.
     * - If the proxy address matches, the function returns `true`, indicating a successful verification.
     *
     * @param response The response data retrieved from the EVMGateway, containing the nonce, registry address, and extra data.
     * @return bool Returns `true` if the proxy address matches the expected address, otherwise the function will revert.
     */
    function verifyCallback(
        bytes calldata response
    ) public view returns (bool) {
        (
            uint256 nonce, //address registryAddress
            ,
            bytes memory extraData
        ) = abi.decode(response, (uint256, address, bytes));
        address proxy = abi.decode(extraData, (address));

        bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));
        bytes memory bytecode = abi.encodePacked(
            type(CustomUpgradeableProxy).creationCode,
            address(0), // placeholder (address(0)) for the registry address or we can use one we ? commented
            address(proxyAdmin)
        );
        address expectedProxyAddress = Create2.computeAddress(
            salt,
            keccak256(bytecode)
        );
        require(expectedProxyAddress == proxy, "Proxy address mismatch");

        // require(registryAddress == REGISTRY_ADDRESS, "Invalid registry address");

        return true;
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
