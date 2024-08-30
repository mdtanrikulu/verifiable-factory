// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ChildContract {
    uint256 public value;
    address public factory;

    constructor(uint256 _value, address _factory) {
        value = _value;
        factory = _factory;
    }
}
