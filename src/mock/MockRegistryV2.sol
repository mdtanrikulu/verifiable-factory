// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockRegistry} from "./MockRegistry.sol";

contract MockRegistryV2 is MockRegistry {
    function getRegistryVersion() public pure override returns (uint256) {
        return 2;
    }
}
