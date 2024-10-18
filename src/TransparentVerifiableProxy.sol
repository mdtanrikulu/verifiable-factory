// SPDX-License-Identifier: MIT

// This contract was adapted from OpenZeppelin's ERC1967Proxy and TransparentUpgradeableProxy implementation.
// @ref: @openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol
// @ref: @openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
pragma solidity ^0.8.20;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

interface ITransparentVerifiableProxy {
    /// @dev See {UUPSUpgradeable-upgradeToAndCall}
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;
}

contract TransparentVerifiableProxy is Proxy, Initializable {
    uint256 public nonce; // Nonce, being used creating the proxy
    address public owner; // The owner of the proxy contract

    // ### EVENTS
    error ProxyDeniedOwnerAccess();

    // // Modifier that allows only the owner to call certain functions
    // modifier onlyOwner() {
    //     require(msg.sender == owner, "Caller is not the owner");
    //     _;
    // }

    /**
     * @dev Initializes the verifiable proxy with an initial implementation specified by `implementation`.
     *
     * If `data` is nonempty, it's used as data in a delegate call to `implementation`. This will typically be an
     * encoded function call, and allows initializing the storage of the proxy like a Solidity constructor.
     *
     * Requirements:
     *
     * - If `data` is empty, `msg.value` must be zero.
     */
    function initialize(
        uint256 _nonce,
        address _owner,
        address implementation,
        bytes memory data
    ) public payable initializer {
        require(
            implementation != address(0),
            "New implementation cannot be the zero address"
        );

        nonce = _nonce;
        owner = _owner;

        ERC1967Utils.upgradeToAndCall(implementation, data);
    }

    /**
     * @dev Returns the current implementation address.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by ERC-1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
     */
    function _implementation()
        internal
        view
        virtual
        override
        returns (address)
    {
        return ERC1967Utils.getImplementation();
    }

    /**
     * @dev If caller is the owner, process the call internally, otherwise transparently fallback to the proxy behavior.
     */
    function _fallback() internal virtual override {
        if (msg.sender == owner) {
            if (
                msg.sig != ITransparentVerifiableProxy.upgradeToAndCall.selector
            ) {
                revert ProxyDeniedOwnerAccess();
            } else {
                _dispatchUpgradeToAndCall();
            }
        } else {
            super._fallback();
        }
    }

    /**
     * @dev Upgrade the implementation of the proxy. See {ERC1967Utils-upgradeToAndCall}.
     *
     * Requirements:
     *
     * - If `data` is empty, `msg.value` must be zero.
     */
    function _dispatchUpgradeToAndCall() private {
        (address newImplementation, bytes memory data) = abi.decode(
            msg.data[4:],
            (address, bytes)
        );
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }

    receive() external payable {}
}
