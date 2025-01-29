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

  struct AddressWeightPair {
    address addr;
    uint8 weight;
  }

  function test_recover_one_signer(
    AddressWeightPair[] calldata _prefix,
    AddressWeightPair[] calldata _suffix,
    Payload.Decoded memory _payload,
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _pk,
    bool _useEthSign
  ) external {
    vm.assume(_prefix.length < 300);
    vm.assume(_suffix.length < 300);

    boundToLegalPayload(_payload);
    _pk = boundPk(_pk);

    address signer = vm.addr(_pk);

    // The signer should not be in the prefix or suffix
    // or we may end up with more weight than expected
    for (uint256 i = 0; i < _prefix.length; i++) {
      vm.assume(_prefix[i].addr != signer);
    }
    for (uint256 i = 0; i < _suffix.length; i++) {
      vm.assume(_suffix[i].addr != signer);
    }

    string memory config;

    {
      string memory ce;
      for (uint256 i = 0; i < _prefix.length; i++) {
        ce = string(
          abi.encodePacked(ce, "signer:", vm.toString(_prefix[i].addr), ":", vm.toString(_prefix[i].weight), " ")
        );
      }

      ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(_weight)));

      for (uint256 i = 0; i < _suffix.length; i++) {
        ce = string(abi.encodePacked(ce, " signer:", vm.toString(_suffix[i].addr), ":", vm.toString(_suffix[i].weight)));
      }

      config = PrimitivesCli.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      bytes32 payloadHash = Payload.hashFor(_payload, address(baseSigImp));

      if (_useEthSign) {
        payloadHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
      }

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, payloadHash);

      string memory signatureType;
      if (_useEthSign) {
        signatureType = ":eth_sign:";
      } else {
        signatureType = ":hash:";
      }

      string memory se = string(
        abi.encodePacked(
          "--signature ", vm.toString(signer), signatureType, vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
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

  function test_recover_one_1271_signer(
    AddressWeightPair[] calldata _prefix,
    AddressWeightPair[] calldata _suffix,
    Payload.Decoded memory _payload,
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    address _signer,
    bytes calldata _signature
  ) external {
    assumeNotPrecompile2(_signer);

    vm.assume(_prefix.length < 300);
    vm.assume(_suffix.length < 300);

    // The signer should not be in the prefix or suffix
    // or we may end up with more weight than expected
    for (uint256 i = 0; i < _prefix.length; i++) {
      vm.assume(_prefix[i].addr != _signer);
    }
    for (uint256 i = 0; i < _suffix.length; i++) {
      vm.assume(_suffix[i].addr != _signer);
    }

    boundToLegalPayload(_payload);

    string memory config;

    {
      string memory ce;
      for (uint256 i = 0; i < _prefix.length; i++) {
        ce = string(
          abi.encodePacked(ce, "signer:", vm.toString(_prefix[i].addr), ":", vm.toString(_prefix[i].weight), " ")
        );
      }

      ce = string(abi.encodePacked(ce, "signer:", vm.toString(_signer), ":", vm.toString(_weight)));

      for (uint256 i = 0; i < _suffix.length; i++) {
        ce = string(abi.encodePacked(ce, " signer:", vm.toString(_suffix[i].addr), ":", vm.toString(_suffix[i].weight)));
      }

      config = PrimitivesCli.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      bytes32 payloadHash = Payload.hashFor(_payload, address(baseSigImp));

      vm.mockCall(
        address(_signer),
        abi.encodeWithSignature("isValidSignature(bytes32,bytes)", payloadHash, _signature),
        abi.encode(bytes4(0x20c13b0b))
      );

      vm.expectCall(
        address(_signer), abi.encodeWithSignature("isValidSignature(bytes32,bytes)", payloadHash, _signature)
      );

      string memory se =
        string(abi.encodePacked("--signature ", vm.toString(_signer), ":erc1271:", vm.toString(_signature)));

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
