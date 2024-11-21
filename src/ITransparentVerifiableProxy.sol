// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransParentVerifiableProxy {
    function salt() external view returns (uint256);

    function owner() external view returns (address);

    function creator() external view returns (address);
}
