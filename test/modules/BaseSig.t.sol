// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { BaseSig } from "../../src/modules/BaseSig.sol";
import { Payload } from "../../src/modules/Payload.sol";
import { PrimitivesCli } from "../utils/PrimitivesCli.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";
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

contract SessionManagerTest is AdvTest {

  BaseSigImp public baseSigImp;

  function setUp() public {
    baseSigImp = new BaseSigImp();
  }

  function test_recover_unsigned(uint16 _threshold, uint56 _checkpoint) external {
    Payload.Decoded memory payload;

    string memory config = PrimitivesCli.newConfig(
      vm, _threshold, _checkpoint, "node:0xac963c4b078c2add1e58444d8b3d08fd6f9131b713d8ed87afc8cb86edb2a198"
    );
    bytes memory encodedConfig = PrimitivesCli.toEncodedConfig(vm, config);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint) =
      baseSigImp.recoverPub(payload, encodedConfig, true);

    assertEq(threshold, _threshold);
    assertEq(weight, 0);
    assertEq(imageHash, PrimitivesCli.getImageHash(vm, config));
    assertEq(checkpoint, _checkpoint);
  }

  function test_recover_one_signer(
    Payload.Decoded memory _payload,
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _pk
  ) external {
    boundToLegalPayload(_payload);
    _pk = boundPk(_pk);

    address signer = vm.addr(_pk);

    string memory config;
    {
      string memory ce = string(abi.encodePacked("signer:", vm.toString(signer), ":", vm.toString(_weight)));
      config = PrimitivesCli.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, Payload.hashFor(_payload, address(baseSigImp)));
      string memory se = string(
        abi.encodePacked(
          "--signature ", vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
        )
      );

      if (_payload.noChainId) {
        se = string(abi.encodePacked(se, " --no-chain-id"));
      }

      encodedSignature = PrimitivesCli.toEncodedSignature(vm, config, se);
    }

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint) =
      baseSigImp.recoverPub(_payload, encodedSignature, true);

    assertEq(threshold, _threshold);
    assertEq(imageHash, PrimitivesCli.getImageHash(vm, config));
    assertEq(checkpoint, _checkpoint);
    assertEq(weight, _weight);
  }

}
