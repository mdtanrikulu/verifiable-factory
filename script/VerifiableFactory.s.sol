// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {VerifiableFactory} from "../src/VerifiableFactory.sol";

contract CounterScript is Script {
    VerifiableFactory public factory;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        string[] memory urls;
        // initialize the ccip-read urls
        urls = new string[](1);
        urls[0] = "";

        factory = new VerifiableFactory(urls, bytes32(0));

        vm.stopBroadcast();
    }
}
