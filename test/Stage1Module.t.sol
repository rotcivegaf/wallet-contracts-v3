// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../src/Factory.sol";
import { Stage1Module } from "../src/Stage1Module.sol";

import { Payload } from "../src/modules/Payload.sol";
import { PrimitivesRPC } from "./utils/PrimitivesRPC.sol";
import { AdvTest } from "./utils/TestUtils.sol";

contract TestStage1Module is AdvTest {

  Factory public factory = new Factory();
  Stage1Module public stage1Module = new Stage1Module(address(factory));

  function test_1271_single_signer(
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _pk,
    bytes32 _digest,
    bool _noChainId
  ) external {
    _threshold = uint16(bound(_threshold, 0, _weight));
    _pk = boundPk(_pk);

    address signer = vm.addr(_pk);

    string memory config;

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(_weight)));
      config = PrimitivesRPC.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes32 configHash = PrimitivesRPC.getImageHash(vm, config);

    // Deploy wallet for that config
    address wallet = factory.deploy(address(stage1Module), configHash);

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;
    payload.noChainId = _noChainId;

    // Sign the config
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(_pk, Payload.hashFor(payload, wallet));

    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      !_noChainId
    );

    // Call isValidSignature
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, signature);
    assertEq(result, bytes4(0x20c13b0b));
  }

}
