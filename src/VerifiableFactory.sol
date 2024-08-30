// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";
import "./ChildContract.sol";

contract VerifiableFactory {
    event ContractCreated(address newContract);

    // function to deploy a ChildContract using CREATE2
    function createContract(uint256 _value) public returns (address) {
        bytes32 salt = generateSalt(msg.sender);
        bytes memory bytecode = getContractBytecode(_value);
        address newContract;

        assembly {
            newContract := create2(
                0,
                add(bytecode, 0x20),
                mload(bytecode),
                salt
            )
            if iszero(extcodesize(newContract)) {
                revert(0, 0)
            }
        }

        emit ContractCreated(newContract);
        return newContract;
    }

    // generates a unique salt based on the sender and the factory's address
    function generateSalt(address user) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), user));
    }

    // verifies if a given address was created by this factory using CREATE2 and if the bytecode matches
    function verifyContract(
        address createdContractAddress,
        uint256 _value,
        address user
    ) public view returns (bool) {
        // first check if the factory address stored in the contract matches
        ChildContract child = ChildContract(createdContractAddress);
        if (child.factory() != address(this)) {
            return false;
        }

        // recalculate the address that should have been created
        bytes32 salt = generateSalt(user);
        bytes memory bytecode = getContractBytecode(_value);

        bytes32 childHash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        address expectedAddress = address(uint160(uint256(childHash)));

        // ensure that the expected address matches with created contract address
        if (expectedAddress != createdContractAddress) {
            return false;
        }

        // retrieve the deployed contract's runtime bytecode hash using extcodehash
        bytes32 deployedBytecodeHash;
        assembly {
            deployedBytecodeHash := extcodehash(createdContractAddress)
        }

        // retrieve the expected runtime bytecode
        bytes32 expectedBytecodeHash = keccak256(
            type(ChildContract).runtimeCode
        );

        return expectedBytecodeHash == deployedBytecodeHash;
    }

    // helper function to get the creation bytecode of the ChildContract
    function getContractBytecode(
        uint256 _value
    ) public view returns (bytes memory) {
        bytes memory bytecode = type(ChildContract).creationCode;
        return abi.encodePacked(bytecode, abi.encode(_value, address(this)));
    }
}
