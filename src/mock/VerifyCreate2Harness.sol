// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VerifiableFactory} from "../VerifiableFactory.sol";

contract VerifyCreate2Harness is VerifiableFactory {
    constructor(string[] memory _urls, bytes32 _rootHash) VerifiableFactory(_urls, _rootHash) {}

    // Deploy this contract then call this method to test `myInternalMethod`.
    function verifyCreate2Harness(address createdContractAddress, uint256 _value, address user)
        external
        view
        returns (bool)
    {
        return verifyCreate2(createdContractAddress, _value, user);
    }
}
