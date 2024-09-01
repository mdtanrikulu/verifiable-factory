// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VerifiableFactory.sol";
import "../src/ChildContract.sol";

// import "../src/mock/VerifyCreate2Harness.sol";

contract FactoryTest is Test {
    VerifiableFactory factory;
    bytes32 merkleRoot;
    string[] urls;

    function setUp() public {
        // static merkle root
        merkleRoot = 0x38fd43fd2274f45a44e9dcb8da9065881f7416a5ba85a5684eee8e2db0e0a1f3;

        // mocking ccip-read urls
        urls = new string[](1);
        urls[0] = "";

        factory = new VerifiableFactory(urls, merkleRoot);
    }

    function testCreateContract() public {
        uint256 value = 42;

        address childContractAddress = factory.createContract(value);

        ChildContract child = ChildContract(childContractAddress);
        assertEq(child.value(), value, "Child contract's value should be correct");
        assertEq(child.factory(), address(factory), "Child contract's factory should be correct");
    }

    // function testVerifyContract() public {
    //     uint256 value = 42;
    //     address user = address(this);

    //     address childContractAddress = factory.createContract(value);

    //     // mock a successful off-chain storage layout verification (skip OffchainLookup for simplicity)
    //     // in a full test, simulate the off-chain verification and invoke verifyCallback manually
    //     // this test only for verifying that the contract was created by the factory

    //     // verify the contract using factory's verifyContract function
    //     // normally this would trigger OffchainLookup; here we're simplifying by calling internal function directly
    //     VerifyCreate2Harness harness = new VerifyCreate2Harness(urls, merkleRoot);
    //     bool result = harness.verifyCreate2Harness(childContractAddress, value, user);
    //     assertTrue(result, "Verification should succeed for valid contract");
    // }

    function testVerifyInvalidContract() public {
        // deploy a ChildContract without the factory
        ChildContract rogueContract = new ChildContract(42, address(factory));

        // verify if it using the factory (this should fail)
        vm.expectRevert(VerifiableFactory.VerificationFailed.selector);
        factory.verifyContract(address(rogueContract), 42, address(this));
    }

    function testVerifyCallback() public view {
        bytes32 layout = bytes32(uint256(0));
        uint256 value = 42;

        // mock merkle proof and leaf for off-chain verification
        bytes32[] memory merkleProof = new bytes32[](1);
        merkleProof[0] = 0xcf5d987e8c58e4cfb73aa2884be6034c1cb96def6945e12657d99532fe2c81b6;

        bytes32 leafHash = keccak256(bytes.concat(keccak256(abi.encode(layout, value))));
        console.logBytes32(leafHash);

        bool result = factory.verifyCallback(merkleProof, leafHash);
        assertTrue(result, "VerificationCallback should succeed with valid Merkle proof");
    }
}
