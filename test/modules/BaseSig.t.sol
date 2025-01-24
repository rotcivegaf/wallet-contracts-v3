// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { BaseSig } from "../../src/modules/BaseSig.sol";

import { Payload } from "../../src/modules/Payload.sol";
import { PrimitivesCli } from "../utils/PrimitivesCli.sol";
import { Test, Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

contract BaseSigImp is BaseSig {

  function recoverPub(
    Payload.Decoded memory _payload,
    bytes calldata _signature,
    bool _ignoreCheckpointer
  ) external view returns (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint) {
    return recover(_payload, _signature, _ignoreCheckpointer);
  }

}

contract SessionManagerTest is Test {

  BaseSigImp public baseSigImp;

  function setUp() public {
    baseSigImp = new BaseSigImp();
  }

  function test_recover_unsigned(uint16 _threshold, uint56 _checkpoint) external {
    Payload.Decoded memory payload;

    string memory config = PrimitivesCli.newConfig(vm, _threshold, _checkpoint);
    bytes memory encodedConfig = PrimitivesCli.toEncodedConfig(vm, config);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint) =
      baseSigImp.recoverPub(payload, encodedConfig, true);

    assertEq(threshold, _threshold);
    assertEq(weight, 0);
    assertEq(imageHash, PrimitivesCli.getImageHash(vm, config));
    assertEq(checkpoint, _checkpoint);
  }

}
