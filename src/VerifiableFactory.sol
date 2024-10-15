// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EVMFetcher} from "@ensdomains/evm-verifier/EVMFetcher.sol";
import {EVMFetchTarget} from "@ensdomains/evm-verifier/EVMFetchTarget.sol";
import {IEVMVerifier} from "@ensdomains/evm-verifier/IEVMVerifier.sol";

import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract ProxyFactory is EVMFetchTarget {
    using EVMFetcher for EVMFetcher.EVMFetchRequest;

    IEVMVerifier public immutable verifier;
    uint256 constant PROXY_NONCE_SLOT = 0;
    uint256 constant PROXY_REGISTRY_SLOT = 1;

    event ProxyDeployed(address indexed proxyAddress);

    constructor(IEVMVerifier _verifier) {
        require(
            address(_verifier) != address(0),
            "Verifier address must be set"
        );
        verifier = _verifier;
    }

    function deployProxy(
        address implementation,
        uint256 nonce
    ) external returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));
        bytes memory data = abi.encodeWithSignature(
            "initialize(uint256)",
            nonce
        );

        address proxy = address(
            new TransparentUpgradeableProxy{salt: salt}(
                implementation,
                address(this),
                data
            )
        );

        require(isContract(proxy), "Proxy deployment failed");

        emit ProxyDeployed(proxy);
        return proxy;
    }

    function updateRegistry(address proxy, address newRegistry) external {
        (bool success, bytes memory result) = proxy.staticcall(
            abi.encodeWithSignature("nonce()")
        );
        require(success, "Failed to retrieve nonce from proxy");
        uint256 proxyNonce = abi.decode(result, (uint256));

        bytes32 salt = keccak256(abi.encodePacked(msg.sender, proxyNonce));
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
        require(
            expectedProxyAddress == proxy,
            "Only the creator can update the registry"
        );

        (success, ) = proxy.call(
            abi.encodeWithSignature("updateRegistry(address)", newRegistry)
        );
        require(success, "Registry update failed");
    }

    function verifyContract(address proxy) public view {
        EVMFetcher
            .newFetchRequest(verifier, proxy)
            .getStatic(PROXY_NONCE_SLOT)
            .getStatic(PROXY_REGISTRY_SLOT)
            .fetch(this.verifyCallback.selector, abi.encode(proxy));
    }

    function verifyCallback(
        bytes calldata response
    ) public view returns (bool) {
        (uint256 nonce, /*address registryAddress*/, bytes memory extraData) = abi
            .decode(response, (uint256, address, bytes));
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

// RegistryProxy Contract
contract RegistryProxy {
    uint256 public nonce;
    address public registry;

    function updateRegistry(address newRegistry) external {
        require(msg.sender == registry, "Only owner can update");
        registry = newRegistry;
    }

    function initialize(uint256 _nonce) external {
        require(nonce == 0, "Already initialized");
        nonce = _nonce;
    }
}
