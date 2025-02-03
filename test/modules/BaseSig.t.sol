// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { BaseSig } from "../../src/modules/BaseSig.sol";
import { Payload } from "../../src/modules/Payload.sol";

import { ISapient, ISapientCompact } from "../../src/modules/interfaces/ISapient.sol";
import { PrimitivesCli } from "../utils/PrimitivesCli.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

contract BaseSigImp is BaseSig {

  function recoverPub(
    Payload.Decoded memory _payload,
    bytes calldata _signature,
    bool _ignoreCheckpointer,
    address _checkpointer
  ) external view returns (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint) {
    return recover(_payload, _signature, _ignoreCheckpointer, _checkpointer);
  }

}

contract BaseSigTest is AdvTest {

  BaseSigImp public baseSigImp;

  function setUp() public {
    baseSigImp = new BaseSigImp();
  }

  function test_recover_random_config_unsigned(uint256 _maxDepth, uint256 _seed) external {
    _maxDepth = bound(_maxDepth, 1, 6);

    Payload.Decoded memory payload;

    string memory config = PrimitivesCli.randomConfig(vm, _maxDepth, _seed);
    bytes memory encodedConfig = PrimitivesCli.toEncodedConfig(vm, config);

    (, uint256 weight, bytes32 imageHash,) = baseSigImp.recoverPub(payload, encodedConfig, true, address(0));

    assertEq(weight, 0);
    assertEq(imageHash, PrimitivesCli.getImageHash(vm, config));
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
    vm.assume(_prefix.length + _suffix.length < 600);

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
      baseSigImp.recoverPub(_payload, encodedSignature, true, address(0));

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
    vm.assume(_prefix.length + _suffix.length < 600);

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
      baseSigImp.recoverPub(_payload, encodedSignature, true, address(0));

    assertEq(threshold, _threshold);
    assertEq(imageHash, PrimitivesCli.getImageHash(vm, config));
    assertEq(checkpoint, _checkpoint);
    assertEq(weight, _weight);
  }

  function test_recover_one_sapient_signer(
    AddressWeightPair[] calldata _prefix,
    AddressWeightPair[] calldata _suffix,
    Payload.Decoded memory _payload,
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    address _signer,
    bytes calldata _signature,
    bytes32 _sapientImageHash,
    bool _isCompact
  ) external {
    assumeNotPrecompile2(_signer);
    vm.assume(_prefix.length + _suffix.length < 600);

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

      ce = string(
        abi.encodePacked(
          ce, "sapient:", vm.toString(_sapientImageHash), ":", vm.toString(_signer), ":", vm.toString(_weight)
        )
      );

      for (uint256 i = 0; i < _suffix.length; i++) {
        ce = string(abi.encodePacked(ce, " signer:", vm.toString(_suffix[i].addr), ":", vm.toString(_suffix[i].weight)));
      }

      config = PrimitivesCli.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      string memory st;

      if (_isCompact) {
        st = ":sapient_compact:";
        bytes32 payloadHash = Payload.hashFor(_payload, address(baseSigImp));

        vm.mockCall(
          address(_signer),
          abi.encodeWithSelector(ISapientCompact.isValidSapientSignatureCompact.selector, payloadHash, _signature),
          abi.encode(_sapientImageHash)
        );

        vm.expectCall(
          address(_signer),
          abi.encodeWithSelector(ISapientCompact.isValidSapientSignatureCompact.selector, payloadHash, _signature)
        );
      } else {
        st = ":sapient:";
        vm.mockCall(
          address(_signer),
          abi.encodeWithSelector(ISapient.isValidSapientSignature.selector, _payload, _signature),
          abi.encode(_sapientImageHash)
        );

        vm.expectCall(
          address(_signer), abi.encodeWithSelector(ISapient.isValidSapientSignature.selector, _payload, _signature)
        );
      }

      string memory se = string(abi.encodePacked("--signature ", vm.toString(_signer), st, vm.toString(_signature)));

      if (_payload.noChainId) {
        se = string(abi.encodePacked(se, " --no-chain-id"));
      }

      encodedSignature = PrimitivesCli.toEncodedSignature(vm, config, se);
    }

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint) =
      baseSigImp.recoverPub(_payload, encodedSignature, true, address(0));

    assertEq(threshold, _threshold);
    assertEq(imageHash, PrimitivesCli.getImageHash(vm, config));
    assertEq(checkpoint, _checkpoint);
    assertEq(weight, _weight);
  }

  function test_recover_nested_config(
    AddressWeightPair[] calldata _prefix,
    AddressWeightPair[] calldata _suffix,
    AddressWeightPair[] calldata _nestedPrefix,
    AddressWeightPair[] calldata _nestedSuffix,
    Payload.Decoded memory _payload,
    uint16 _threshold,
    uint56 _checkpoint,
    uint16 _internalThreshold,
    uint8 _externalWeight,
    uint8 _weight,
    uint256 _pk,
    bool _useEthSign
  ) external {
    vm.assume(_prefix.length + _suffix.length + _nestedPrefix.length + _nestedSuffix.length < 600);

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

    for (uint256 i = 0; i < _nestedPrefix.length; i++) {
      vm.assume(_nestedPrefix[i].addr != signer);
    }
    for (uint256 i = 0; i < _nestedSuffix.length; i++) {
      vm.assume(_nestedSuffix[i].addr != signer);
    }

    string memory config;

    {
      string memory ce;
      for (uint256 i = 0; i < _prefix.length; i++) {
        ce = string(
          abi.encodePacked(ce, "signer:", vm.toString(_prefix[i].addr), ":", vm.toString(_prefix[i].weight), " ")
        );
      }

      string memory nestedContent;
      for (uint256 i = 0; i < _nestedPrefix.length; i++) {
        nestedContent = string(
          abi.encodePacked(
            nestedContent, "signer:", vm.toString(_nestedPrefix[i].addr), ":", vm.toString(_nestedPrefix[i].weight), " "
          )
        );
      }

      nestedContent = string(abi.encodePacked(nestedContent, "signer:", vm.toString(signer), ":", vm.toString(_weight)));

      for (uint256 i = 0; i < _nestedSuffix.length; i++) {
        nestedContent = string(
          abi.encodePacked(
            nestedContent, " signer:", vm.toString(_nestedSuffix[i].addr), ":", vm.toString(_nestedSuffix[i].weight)
          )
        );
      }

      ce = string(
        abi.encodePacked(
          ce, "nested:", vm.toString(_internalThreshold), ":", vm.toString(_externalWeight), ":(", nestedContent, ")"
        )
      );

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
      baseSigImp.recoverPub(_payload, encodedSignature, true, address(0));

    assertEq(threshold, _threshold);
    assertEq(imageHash, PrimitivesCli.getImageHash(vm, config));
    assertEq(checkpoint, _checkpoint);
    assertEq(weight, _weight >= _internalThreshold ? _externalWeight : 0);
  }

}
