// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {VerifiableFactory} from "../src/VerifiableFactory.sol";

contract CounterScript is Script {
    VerifiableFactory public factory;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // TODO complete it
        VerifiableFactory.Verifiers[] memory verifiers = new VerifiableFactory.Verifiers[](3);
        verifiers[0] = VerifiableFactory.Verifiers({networkId: 1, verifier: address(0)});
        verifiers[1] = VerifiableFactory.Verifiers({networkId: 42, verifier: address(0)});
        verifiers[2] = VerifiableFactory.Verifiers({networkId: 137, verifier: address(0)});

        factory = new VerifiableFactory(verifiers);

        vm.stopBroadcast();
    }
}
