// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../src/Factory.sol";
import { Stage1Module } from "../src/Stage1Module.sol";
import { Stage2Module } from "../src/Stage2Module.sol";

import { Payload } from "../src/modules/Payload.sol";

import { BaseAuth } from "../src/modules/auth/BaseAuth.sol";

import { SelfAuth } from "../src/modules/auth/SelfAuth.sol";
import { PrimitivesRPC } from "./utils/PrimitivesRPC.sol";
import { AdvTest } from "./utils/TestUtils.sol";

contract TestStage1Module is AdvTest {

  Factory public factory = new Factory();
  Stage1Module public stage1Module = new Stage1Module(address(factory));

  event StaticSignatureSet(bytes32 _hash, address _address, uint96 _timestamp);

  function test_fails_on_low_weight(
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _pk,
    bytes32 _digest,
    bool _noChainId
  ) external {
    _weight = uint8(bound(_weight, 1, type(uint8).max));
    _threshold = uint16(bound(_threshold, 1, _weight));
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
    address payable wallet = payable(factory.deploy(address(stage1Module), configHash));

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;
    payload.noChainId = _noChainId;

    // Create a signature with only nodes
    bytes memory signature = PrimitivesRPC.toEncodedSignature(vm, config, "", !_noChainId);

    // Call isValidSignature and expect it to fail
    vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidSignatureWeight.selector, _threshold, 0));
    Stage1Module(wallet).isValidSignature(_digest, signature);
  }

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
    address payable wallet = payable(factory.deploy(address(stage1Module), configHash));

    // Should predict the address of the wallet using the SDK
    address predictedWallet = PrimitivesRPC.getAddress(vm, configHash, address(factory), address(stage1Module));
    assertEq(wallet, predictedWallet);

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

  struct test_update_config_params {
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    uint256 pk;
    bool noChainId;
    // Next config parameters
    uint16 nextThreshold;
    uint56 nextCheckpoint;
    uint8 nextWeight;
    uint256 nextPk;
    // Test transaction parameters
    bytes32 digest;
  }

  struct test_update_config_vars {
    address ogSigner;
    address nextSigner;
    string ogConfig;
    string nextConfig;
    bytes32 ogConfigHash;
    bytes32 nextConfigHash;
    Payload.Decoded updateConfigPayload;
    bytes updateConfigSignature;
    bytes updateConfigPackedPayload;
    Payload.Decoded useNewImageHashPayload;
    bytes useNewImageHashSignature;
  }

  function test_update_config(
    test_update_config_params memory params
  ) external {
    params.pk = boundPk(params.pk);
    params.nextPk = boundPk(params.nextPk);
    params.threshold = uint16(bound(params.threshold, 0, params.weight));
    params.nextThreshold = uint16(bound(params.nextThreshold, 0, params.nextWeight));

    test_update_config_vars memory vars;

    vars.ogSigner = vm.addr(params.pk);

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.ogSigner), ":", vm.toString(params.weight)));
      vars.ogConfig = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    }

    vars.ogConfigHash = PrimitivesRPC.getImageHash(vm, vars.ogConfig);

    // Deploy wallet for that config
    address payable wallet = payable(factory.deploy(address(stage1Module), vars.ogConfigHash));

    vars.nextSigner = vm.addr(params.nextPk);

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.nextSigner), ":", vm.toString(params.nextWeight)));
      vars.nextConfig = PrimitivesRPC.newConfig(vm, params.nextThreshold, params.nextCheckpoint, ce);
    }

    vars.nextConfigHash = PrimitivesRPC.getImageHash(vm, vars.nextConfig);

    // Update configuration to the next config
    vars.updateConfigPayload.kind = Payload.KIND_TRANSACTIONS;
    vars.updateConfigPayload.calls = new Payload.Call[](1);
    vars.updateConfigPayload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, vars.nextConfigHash),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    vars.updateConfigPayload.noChainId = params.noChainId;

    {
      // Sign the payload
      (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.pk, Payload.hashFor(vars.updateConfigPayload, wallet));

      // Call updateConfig
      vars.updateConfigSignature = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.ogConfig,
        string(
          abi.encodePacked(
            vm.toString(vars.ogSigner), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
          )
        ),
        !params.noChainId
      );
    }

    // Pack payload
    vars.updateConfigPackedPayload = PrimitivesRPC.toPackedPayload(vm, vars.updateConfigPayload);

    // Perform updateConfig
    Stage1Module(wallet).execute(vars.updateConfigPackedPayload, vars.updateConfigSignature);

    // Now the wallet should be at stage 2
    // and its imageHash should be updated
    assertEq(Stage1Module(wallet).getImplementation(), stage1Module.STAGE_2_IMPLEMENTATION());
    assertEq(Stage2Module(wallet).imageHash(), vars.nextConfigHash);

    // Now try to use the new imageHash
    vars.useNewImageHashPayload.kind = Payload.KIND_DIGEST;
    vars.useNewImageHashPayload.digest = params.digest;

    // Sign the payload
    {
      (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.nextPk, Payload.hashFor(vars.useNewImageHashPayload, wallet));

      vars.useNewImageHashSignature = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.nextConfig,
        string(
          abi.encodePacked(
            vm.toString(vars.nextSigner), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
          )
        ),
        true
      );
    }

    bytes4 result = Stage2Module(wallet).isValidSignature(params.digest, vars.useNewImageHashSignature);
    assertEq(result, bytes4(0x20c13b0b));
  }

  function test_receiveETH_stage1() external {
    address payable wallet = payable(factory.deploy(address(stage1Module), bytes32(0)));
    vm.deal(address(this), 1 ether);
    wallet.transfer(1 ether);
    assertEq(address(wallet).balance, 1 ether);
  }

  struct test_receiveETH_stage2_params {
    uint256 pk;
    uint256 nextPk;
    uint16 threshold;
    uint16 nextThreshold;
    uint56 checkpoint;
  }

  struct test_receiveETH_stage2_vars {
    address signer;
    address payable wallet;
    bytes updateConfigSignature;
    bytes updateConfigPackedPayload;
    string ogCe;
    string ogConfig;
    string nextCe;
    string nextConfig;
    bytes32 ogConfigHash;
    bytes32 nextConfigHash;
  }

  function test_receiveETH_stage2(
    test_receiveETH_stage2_params memory params
  ) external {
    params.pk = boundPk(params.pk);

    test_receiveETH_stage2_vars memory vars;
    vars.signer = vm.addr(params.pk);

    // Original config (stage1)
    vars.ogCe = string(abi.encodePacked("signer:", vm.toString(vars.signer), ":1"));
    vars.ogConfig = PrimitivesRPC.newConfig(vm, 1, 0, vars.ogCe);
    vars.ogConfigHash = PrimitivesRPC.getImageHash(vm, vars.ogConfig);

    // Deploy wallet in stage1
    vars.wallet = payable(factory.deploy(address(stage1Module), vars.ogConfigHash));

    // Next config (what we'll update to)
    vars.nextCe = string(abi.encodePacked("signer:", vm.toString(vars.signer), ":1"));
    vars.nextConfig = PrimitivesRPC.newConfig(vm, 1, 1, vars.nextCe);
    vars.nextConfigHash = PrimitivesRPC.getImageHash(vm, vars.nextConfig);

    // Construct the payload to update the imageHash (which transitions us to stage2)
    Payload.Decoded memory updateConfigPayload;
    updateConfigPayload.kind = Payload.KIND_TRANSACTIONS;
    updateConfigPayload.calls = new Payload.Call[](1);
    updateConfigPayload.calls[0] = Payload.Call({
      to: address(vars.wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, vars.nextConfigHash),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Sign the payload using the original config
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.pk, Payload.hashFor(updateConfigPayload, vars.wallet));
    vars.updateConfigSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      vars.ogConfig,
      string(
        abi.encodePacked(vm.toString(vars.signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
      ),
      true
    );

    // Pack the payload and execute
    vars.updateConfigPackedPayload = PrimitivesRPC.toPackedPayload(vm, updateConfigPayload);
    Stage1Module(vars.wallet).execute(vars.updateConfigPackedPayload, vars.updateConfigSignature);

    // Confirm that the wallet is now running stage2
    assertEq(Stage1Module(vars.wallet).getImplementation(), stage1Module.STAGE_2_IMPLEMENTATION());

    // Send 1 ether to the newly upgraded wallet
    vm.deal(address(this), 1 ether);
    vars.wallet.transfer(1 ether);

    // Check that the wallet received the ether
    assertEq(address(vars.wallet).balance, 1 ether);
  }

  function test_static_signature_any_address(
    bytes32 _digest,
    bytes32 _imageHash,
    uint256 _timestamp,
    uint256 _validUntil,
    address _otherCaller
  ) external {
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;

    _timestamp = bound(_timestamp, 0, type(uint64).max);
    _validUntil = bound(_validUntil, _timestamp + 1, type(uint96).max);

    vm.warp(_timestamp);

    // Create a new wallet using imageHash
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Set the static signature
    vm.prank(wallet);
    vm.expectEmit(true, true, false, true, wallet);
    emit StaticSignatureSet(Payload.hashFor(payload, wallet), address(0), uint96(_validUntil));
    Stage1Module(wallet).setStaticSignature(Payload.hashFor(payload, wallet), address(0), uint96(_validUntil));

    (address addr, uint256 timestamp) = Stage1Module(wallet).getStaticSignature(Payload.hashFor(payload, wallet));
    assertEq(addr, address(0));
    assertEq(timestamp, _validUntil);

    // Call isValidSignature and expect it to succeed
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x20c13b0b));

    // Even if called from other caller
    vm.prank(_otherCaller);
    result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x20c13b0b));
  }

  function test_static_signature_specific_address(
    bytes32 _digest,
    bytes32 _imageHash,
    uint256 _timestamp,
    uint256 _validUntil,
    address _onlyAddress,
    address _otherCaller
  ) external {
    vm.assume(_onlyAddress != address(0) && _onlyAddress != _otherCaller);

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;

    _timestamp = bound(_timestamp, 0, type(uint64).max);
    _validUntil = bound(_validUntil, _timestamp + 1, type(uint96).max);

    vm.warp(_timestamp);

    // Create a new wallet using imageHash
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Set the static signature
    vm.prank(wallet);
    vm.expectEmit(true, true, false, true, wallet);
    emit StaticSignatureSet(Payload.hashFor(payload, wallet), _onlyAddress, uint96(_validUntil));
    Stage1Module(wallet).setStaticSignature(Payload.hashFor(payload, wallet), _onlyAddress, uint96(_validUntil));

    (address addr, uint256 timestamp) = Stage1Module(wallet).getStaticSignature(Payload.hashFor(payload, wallet));
    assertEq(addr, _onlyAddress);
    assertEq(timestamp, _validUntil);

    // Call isValidSignature from _onlyAddress should succeed
    vm.prank(_onlyAddress);
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x20c13b0b));

    // Call isValidSignature from _otherCaller should fail
    vm.prank(_otherCaller);
    vm.expectRevert(
      abi.encodeWithSelector(
        BaseAuth.InvalidStaticSignatureWrongCaller.selector,
        Payload.hashFor(payload, wallet),
        _otherCaller,
        _onlyAddress
      )
    );
    Stage1Module(wallet).isValidSignature(_digest, hex"80");
  }

  function test_reverts_invalid_static_signature_expired(
    bytes32 _digest,
    bytes32 _imageHash,
    uint256 _startTime,
    uint256 _validUntil
  ) external {
    // Ensure validUntil is strictly after startTime and within uint96 range
    _startTime = bound(_startTime, 0, type(uint96).max - 1);
    _validUntil = bound(_validUntil, _startTime + 1, type(uint96).max);

    // Set the current time to _startTime
    vm.warp(_startTime);

    // Create a new wallet
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Prepare the payload and calculate its hash
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;
    bytes32 opHash = Payload.hashFor(payload, wallet);

    // Set the static signature from the wallet itself, valid until _validUntil
    // Use address(0) to allow any caller before expiration
    vm.prank(wallet);
    vm.expectEmit(true, true, false, true, wallet);
    emit StaticSignatureSet(opHash, address(0), uint96(_validUntil));
    Stage1Module(wallet).setStaticSignature(opHash, address(0), uint96(_validUntil));

    // Verify it was set correctly
    (address addr, uint256 timestamp) = Stage1Module(wallet).getStaticSignature(opHash);
    assertEq(addr, address(0));
    assertEq(timestamp, _validUntil);

    // --- Test Case 1: Use signature just before expiry (should work) ---
    vm.warp(_validUntil - 1); // Set time to just before expiration
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x20c13b0b), "Signature should be valid before expiry");

    // --- Test Case 2: Use signature exactly at expiry (should fail) ---
    vm.warp(_validUntil); // Set time exactly to expiration
    vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureExpired.selector, opHash, _validUntil));
    Stage1Module(wallet).isValidSignature(_digest, hex"80");

    // --- Test Case 3: Use signature after expiry (should fail) ---
    vm.warp(_validUntil + 1); // Set time after expiration
    vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureExpired.selector, opHash, _validUntil));
    Stage1Module(wallet).isValidSignature(_digest, hex"80");
  }

  function test_reverts_set_static_signature_not_self(
    bytes32 _hash,
    bytes32 _imageHash,
    address _sigAddress,
    uint96 _timestamp,
    address _caller // The address attempting the call (not the wallet)
  ) external {
    // Create a new wallet
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Ensure the caller is not the wallet itself
    vm.assume(_caller != wallet);

    // Attempt to call setStaticSignature from _caller
    vm.prank(_caller);
    vm.expectRevert(abi.encodeWithSelector(SelfAuth.OnlySelf.selector, _caller));
    Stage1Module(wallet).setStaticSignature(_hash, _sigAddress, _timestamp);

    // Verify that the signature was NOT set (should still be default values)
    (address addr, uint256 ts) = Stage1Module(wallet).getStaticSignature(_hash);
    assertEq(addr, address(0), "Static signature address should not be set");
    assertEq(ts, 0, "Static signature timestamp should not be set");
  }

  receive() external payable { }

}
