// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EVMFetcher} from "@ensdomains/evm-verifier/EVMFetcher.sol";
import {EVMFetchTarget} from "@ensdomains/evm-verifier/EVMFetchTarget.sol";
import {IEVMVerifier} from "@ensdomains/evm-verifier/IEVMVerifier.sol";

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import { RegistryProxy } from './RegistryProxy.sol';

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
            verifiers[_verifiers[i].networkId] = IEVMVerifier(_verifiers[i].verifier);
        }

        proxyAdmin = new ProxyAdmin(address(this));
    }


    /**
     * @dev deploys a new `TransparentUpgradeableProxy` contract using a deterministic address derived from
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
     * @return proxy The address of the deployed `TransparentUpgradeableProxy` contract.
     */
    function deployProxy(uint256 nonce) external returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));
        bytes memory data = abi.encodeWithSignature(
            "initialize(uint256)",
            nonce,
            address(proxyAdmin)
        );

        RegistryProxy proxyInstance = new RegistryProxy();
        address proxy = address(
            new TransparentUpgradeableProxy{salt: salt}(
                address(proxyInstance),
                address(proxyAdmin),
                data
            )
        );

        require(isContract(proxy), "Proxy deployment failed");

        emit ProxyDeployed(proxy);
        return proxy;
    }

    function updateRegistry(address proxy, address newImplementation) external {
        // todo        
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
    function verifyContract(address proxy, uint256 networkId) public view {
        IEVMVerifier verifier = verifiers[networkId];
        require(address(verifier) != address(0), "Verifier is not available for the given netowrk");

        EVMFetcher
            .newFetchRequest(verifiers[networkId], proxy)
            .getStatic(PROXY_NONCE_SLOT)
            .getStatic(PROXY_REGISTRY_SLOT)
            .fetch(this.verifyCallback.selector, abi.encode(proxy));
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
            uint256 nonce /*address registryAddress*/,
            ,
            bytes memory extraData
        ) = abi.decode(response, (uint256, address, bytes));
        address proxy = abi.decode(extraData, (address));

        bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));
        address expectedProxyAddress = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            salt,
                            keccak256(
                                type(TransparentUpgradeableProxy).creationCode
                            )
                        )
                    )
                )
            )
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
