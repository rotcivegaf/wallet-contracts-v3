// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import { Vm } from "forge-std/Test.sol";

using PrimitivesCli for Vm;

library PrimitivesCli {

  // TODO: Move to ENV
  function root() internal pure returns (string[] memory) {
    string[] memory r = new string[](2);
    r[0] = "node";
    r[1] = "../sequence-core/packages/primitives-cli/dist/index.js";
    return r;
  }

  function runRoot(Vm _vm, string[] memory _args) internal returns (bytes memory) {
    string[] memory r = root();
    string[] memory inputs = new string[](_args.length + r.length);

    for (uint256 i = 0; i < r.length; i++) {
      inputs[i] = r[i];
    }
    for (uint256 i = 0; i < _args.length; i++) {
      inputs[i + r.length] = _args[i];
    }

    return _vm.ffi(inputs);
  }

  function toPacked(Vm _vm, Payload.Decoded memory _decoded) internal returns (bytes memory) {
    string[] memory args = new string[](3);
    args[0] = "payload";
    args[1] = "to-packed";
    args[2] = _vm.toString(abi.encode(_decoded));
    return _vm.runRoot(args);
  }

}
