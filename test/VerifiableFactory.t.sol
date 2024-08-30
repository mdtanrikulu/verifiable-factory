// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VerifiableFactory.sol";
import "../src/ChildContract.sol";

contract FactoryTest is Test {
    VerifiableFactory factory;

    function setUp() public {
        factory = new VerifiableFactory();
    }

    function testCreateContract() public {
        // define value to pass to ChildContract's constructor
        uint256 value = 42;

        // call createContract and deploy ChildContract using the factory
        address childContractAddress = factory.createContract(value);

        // verify the deployed ChildContract has the expected value and factory address
        ChildContract child = ChildContract(childContractAddress);
        assertEq(child.value(), value, "Child contract's value should be correct");
        assertEq(child.factory(), address(factory), "Child contract's factory should be correct");
    }

    function testVerifyContract() public {
        // define value to pass to ChildContract's constructor
        uint256 value = 42;
        address user = address(this);

        // deploy the ChildContract via the factory
        address childContractAddress = factory.createContract(value);

        // verify the contract using factory's verifyContract function
        bool result = factory.verifyContract(childContractAddress, value, user);
        assertTrue(result, "Verification should succeed for valid contract");
    }

    function testVerifyInvalidContract() public {
        // deploy a ChildContract without the factory
        ChildContract rogueContract = new ChildContract(42, address(factory));

        // try to verify it using the factory (this should fail)
        bool result = factory.verifyContract(address(rogueContract), 42, address(this));
        assertFalse(result, "Verification should fail for contract not deployed by factory");
    }

    // function testVerifyInvalidContract2() public {
    //     bytes32 salt = generateSalt(address(this));
    //     bytes memory bytecode = getContractBytecode(42);
    //     address rogueContract;
    //     assembly {
    //         rogueContract := create2(
    //             0,
    //             add(bytecode, 0x20),
    //             mload(bytecode),
    //             salt
    //         )
    //         if iszero(extcodesize(rogueContract)) {
    //             revert(0, 0)
    //         }
    //     }

    //     bool result = factory.verifyContract(rogueContract, 42, address(this));
    //     assertFalse(result, "Verification should fail for contract not deployed by factory");
    // }

    // function generateSalt(address user) internal view returns (bytes32) {
    //     return keccak256(abi.encodePacked(address(factory), user));
    // }

    // function getContractBytecode(
    //     uint256 _value
    // ) public view returns (bytes memory) {
    //     bytes memory bytecode = type(ChildContract).creationCode;
    //     return abi.encodePacked(bytecode, abi.encode(_value, address(factory)));
    // }
}
