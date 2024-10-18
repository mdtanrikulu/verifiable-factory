// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ITransparentVerifiableProxy, TransparentVerifiableProxy} from "./TransparentVerifiableProxy.sol";

interface IProxy {
    function salt() external view returns (uint256);

    function owner() external view returns (address);
}

contract VerifiableFactory {

    event ProxyDeployed(
        address indexed sender,
        address indexed proxyAddress,
        uint256 salt,
        address implementation
    );

    constructor() {}

    /**
     * @dev Deploys a new `TransparentVerifiableProxy` contract at a deterministic address.
     *
     * This function deploys a proxy contract using the CREATE2 opcode, ensuring a predictable 
     * address based on the sender's address and a provided salt. The deployed proxy is 
     * controlled by the factory and is initialized to use a specific implementation.
     *
     * - A unique address for the proxy is generated using the caller's address and the salt.
     * - After deployment, the proxy's `initialize` function is called to configure it with the given salt, 
     *   the factory address, and the provided implementation address.
     * - The proxy is fully managed by the factory, which controls upgrades and other administrative methods.
     * - The event `ProxyDeployed` is emitted, logging details of the deployment including the sender, proxy address, salt, and implementation.
     *
     * @param implementation The address of the contract implementation the proxy will delegate calls to.
     * @param salt A value provided by the caller to ensure uniqueness of the proxy address.
     * @return proxy The address of the deployed `TransparentVerifiableProxy`.
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
     * @dev Initiates verification of a proxy contract.
     *
     * This function attempts to validate a proxy contract by retrieving its salt 
     * and reconstructing the address to ensure it was correctly deployed by the 
     * current factory.
     *
     * @param proxy The address of the proxy contract being verified.
     * @return A boolean indicating whether the verification succeeded.
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
