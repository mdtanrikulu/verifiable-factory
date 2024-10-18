// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ITransparentVerifiableProxy, TransparentVerifiableProxy} from "./TransparentVerifiableProxy.sol";

interface IProxy {
    function salt() external view returns (uint256);

    function owner() external view returns (address);
}

contract VerifiableFactory {
    uint256 constant PROXY_NONCE_SLOT = 0;
    uint256 constant PROXY_REGISTRY_SLOT = 1;

    event ProxyDeployed(
        address indexed sender,
        address indexed proxyAddress,
        uint256 salt,
        address implementation
    );

    constructor() {}

    /**
     * @dev deploys a new `TransparentVerifiableProxy` contract using a deterministic address derived from
     *      the sender's address and a salt.
     *
     * The function creates a new proxy contract that is controlled by the factory's `ProxyAdmin`.
     * When the proxy is deployed, it starts by using the `RegistryProxy` contract as its main implementation.
     * During the deployment, the initialize function is called to set up the proxy.
     * The salt ensures that each user gets a unique proxy, even if the same user deploys multiple proxies.
     *
     * - The function uses a `salt` to create a deterministic address based on `msg.sender` and a provided salt.
     * - The `initialize` function of the `RegistryProxy` contract is called immediately after deployment to set up
     *   the proxy with the salt and `ProxyAdmin`.
     * - The proxy is managed by a `ProxyAdmin` contract, ensuring that upgrades and critical functions are restricted to the admin.
     * - A custom event `ProxyDeployed` is emitted to track the deployment of the new proxy.
     *
     * @param implementation Registry implementation address
     * @param salt A unique number provided by the caller to create a unique proxy address.
     * @return proxy The address of the deployed `TransparentVerifiableProxy` contract.
     */
    function deployProxy(
        address implementation,
        uint256 salt
    ) external returns (address) {
        bytes32 outerSalt = keccak256(abi.encode(msg.sender, salt));

        TransparentVerifiableProxy proxy = new TransparentVerifiableProxy{
            salt: outerSalt
        }();

        require(isContract(address(proxy)), "Proxy deployment failed");

        proxy.initialize(salt, address(this), implementation, "");

        emit ProxyDeployed(msg.sender, address(proxy), salt, implementation);
        return address(proxy);
    }

    // Function to upgrade the proxy's implementation (only owner of proxy can call this)
    function upgradeImplementation(
        address proxyAddress,
        address newImplementation,
        bytes memory data
    ) external {
        require(verifyContract(proxyAddress), "Only the owner can upgrade");

        // Upgrade the proxy to point to the new implementation
        ITransparentVerifiableProxy(payable(proxyAddress)).upgradeToAndCall(
            newImplementation,
            data
        );
    }

    /**
     * @dev VerifyContract method for both same-chain verification
     *
     * The function starts the process of verifying a specific proxy contract by sending a request
     *
     *
     * - It retrieves static values from storage slots (`PROXY_NONCE_SLOT` and `PROXY_REGISTRY_SLOT`) to assist in the verification process.
     *
     * @param proxy The address of the proxy contract to be verified.
     */
    function verifyContract(address proxy) public view returns (bool) {
        // directly fetch storage
        try IProxy(proxy).salt() returns (uint256 salt) {
            address owner = IProxy(proxy).owner();

            require(
                address(this) == owner,
                "Proxy owner does not match with factory address"
            );

            // reconstruct the address using CREATE2 and the original salt
            bytes32 outerSalt = keccak256(abi.encode(msg.sender, salt));

            // bytes memory bytecode = abi.encodePacked(
            //     type(TransparentVerifiableProxy).creationCode,
            //     abi.encode(salt, address(this))
            // );

            // Compute the expected proxy address using the outerSalt
            address expectedProxyAddress = Create2.computeAddress(
                outerSalt,
                keccak256(type(TransparentVerifiableProxy).creationCode)
            );

            // Verify if the computed address matches the proxy address
            require(expectedProxyAddress == proxy, "Proxy address mismatch");

            return true;
        } catch {
            return false;
        }
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
