// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import { PrimitivesCli } from "../utils/PrimitivesCli.sol";
import { Test, Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

contract PayloadImp {

  function fromPackedCalls(
    bytes calldata packed
  ) external view returns (Payload.Decoded memory) {
    return Payload.fromPackedCalls(packed);
  }

}

contract SessionManagerTest is Test {

  PayloadImp public payloadImp;

  function setUp() public {
    payloadImp = new PayloadImp();
  }

  function test_fromPackedCalls(Payload.Call[] memory _calls, uint256 _space, uint256 _nonce) external {
    vm.assume(_calls.length < type(uint16).max);

    // Convert nonce into legal range
    _nonce = bound(_nonce, 0, type(uint56).max);
    _space = bound(_space, 0, type(uint160).max);

    for (uint256 i = 0; i < _calls.length; i++) {
      // Convert behaviors into legal ones
      _calls[i].behaviorOnError = bound(
        _calls[i].behaviorOnError, uint256(Payload.BEHAVIOR_IGNORE_ERROR), uint256(Payload.BEHAVIOR_ABORT_ON_ERROR)
      );
    }

    Payload.Decoded memory input;
    input.kind = Payload.KIND_TRANSACTIONS;
    input.calls = _calls;
    input.space = _space;
    input.nonce = _nonce;

    bytes memory packed = PrimitivesCli.toPackedPayload(vm, input);
    console.logBytes(packed);

    Payload.Decoded memory output = payloadImp.fromPackedCalls(packed);
    console.logBytes(abi.encode(output));

    // Input should equal output
    assertEq(abi.encode(input), abi.encode(output));
  }

}
