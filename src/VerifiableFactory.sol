// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";
import "./ChildContract.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract VerifiableFactory {
    using Address for address;

    event ContractCreated(address newContract);

    error VerificationFailed();
    error OffchainLookup(string[] urls, bytes callData);

    string[] public urls;
    bytes32 public rootHash;

    constructor(string[] memory _urls, bytes32 _rootHash) {
        urls = _urls;
        rootHash = _rootHash;
    }

    // function to deploy a ChildContract using CREATE2
    function createContract(uint256 _value) public returns (address) {
        bytes32 salt = generateSalt(msg.sender);
        bytes memory bytecode = getContractBytecode(_value);
        address newContract;

        assembly {
            newContract := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(newContract)) { revert(0, 0) }
        }

        emit ContractCreated(newContract);
        return newContract;
    }

    // verification function that includes both bytecode and storage verification
    function verifyContract(address createdContractAddress, uint256 _value, address user)
        public
        view
        returns (bytes memory)
    {
        // verify using CREATE2 and bytecode
        if (!verifyCreate2(createdContractAddress, _value, user)) {
            revert VerificationFailed();
        }

        revert OffchainLookup(urls, abi.encode(createdContractAddress, _value, user));
    }

    // callback to complete storage verification after off-chain proof (ccip-read)
    function verifyCallback(bytes32[] calldata merkleProof, bytes32 leafHash) public view returns (bool) {
        // Verify the Merkle proof using the stored rootHash
        bool isValid = MerkleProof.verify(merkleProof, rootHash, leafHash);
        require(isValid, "VerificationFailed");
        return true;
    }

    // helper function to perform CREATE2 and extcodehash checks
    function verifyCreate2(address createdContractAddress, uint256 _value, address user) internal view returns (bool) {
        // recalculate the address that should have been created
        bytes32 salt = generateSalt(user);
        bytes memory bytecode = getContractBytecode(_value);
        bytes32 childHash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode)));
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
        bytes32 expectedBytecodeHash = keccak256(type(ChildContract).runtimeCode);

        return expectedBytecodeHash == deployedBytecodeHash;
    }

    // helper function to get the creation bytecode of the ChildContract
    function getContractBytecode(uint256 _value) public view returns (bytes memory) {
        bytes memory bytecode = type(ChildContract).creationCode;
        return abi.encodePacked(bytecode, abi.encode(_value, address(this)));
    }

    // generates a unique salt based on the sender and the factory's address
    function generateSalt(address user) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), user));
    }
}
