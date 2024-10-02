// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";
import "./ChildContract.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/Address.sol";

import {EVMFetcher} from "@ensdomains/evm-verifier/EVMFetcher.sol";
import {EVMFetchTarget} from "@ensdomains/evm-verifier/EVMFetchTarget.sol";
import {IEVMVerifier} from "@ensdomains/evm-verifier/IEVMVerifier.sol";

// import {ClonesWithImmutableArgs} from "clones-with-immutable-args/ClonesWithImmutableArgs.sol";

interface IVerifiableContract {
    function verifyStorageLayout(
        address contractAddress,
        bytes32 slot,
        uint256 value
    ) external returns (bytes memory);
}

contract VerifiableFactory is EVMFetchTarget {
    using Address for address;
    using EVMFetcher for EVMFetcher.EVMFetchRequest;

    event ContractCreated(address newContract);
    error VerificationFailed();
    error OffchainLookup(
        address sender,
        string[] urls,
        bytes callData,
        bytes4 callbackFunction,
        bytes extraData
    );

    IEVMVerifier public immutable verifier;
    uint256 constant CONTRACT_REGISTRY_SLOT = 0;

    constructor(IEVMVerifier _verifier) {
        require(
            address(_verifier) != address(0),
            "Verifier address must be set"
        );
        verifier = _verifier;
    }

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

    // verification function that includes both bytecode and storage verification
    function verifyContract(
        address target,
        uint256 _value,
        address user
    ) public view returns (bytes memory) {
        // verify using CREATE2 and bytecode
        if (!verifyCreate2(target, _value, user)) {
            revert VerificationFailed();
        }

        EVMFetcher
            .newFetchRequest(verifier, target)
            .getStatic(CONTRACT_REGISTRY_SLOT)
            .fetch(this.verifyCallback.selector, "");
    }

    // callback to complete storage verification after off-chain proof (ccip-read)
    function verifyCallback(
        bytes calldata response
    ) public pure returns (bool) {
        address registry = abi.decode(response, (address));
        return true;
    }

    // helper function to perform CREATE2 and extcodehash checks
    function verifyCreate2(
        address createdContractAddress,
        uint256 _value,
        address user
    ) internal view returns (bool) {
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

    // generates a unique salt based on the sender and the factory's address
    function generateSalt(address user) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), user));
    }
}
