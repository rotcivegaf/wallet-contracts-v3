// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm, console } from "forge-std/Test.sol";

import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { AcceptAll } from "test/mocks/AcceptAll.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import {
  SessionErrors, SessionManager, SessionPermissions, SessionSig
} from "src/extensions/sessions/SessionManager.sol";
import { ParameterRule, Permission } from "src/extensions/sessions/explicit/Permission.sol";
import { Payload } from "src/modules/Payload.sol";

/// @notice Session signature abuse tests.
contract ExtendedSessionTestBase is SessionTestBase {

  Factory public factory;
  Stage1Module public module;
  SessionManager public sessionManager;
  Vm.Wallet public sessionWallet;
  Vm.Wallet public identityWallet;
  AcceptAll public mockTarget;

  function setUp() public {
    sessionWallet = vm.createWallet("session");
    identityWallet = vm.createWallet("identity");
    sessionManager = new SessionManager();
    factory = new Factory();
    module = new Stage1Module(address(factory), address(0));
  }

  function _createDefaultTopology() internal returns (string memory topology) {
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: address(mockTarget), rules: new ParameterRule[](0) });
    return _createTopology(sessionPerms);
  }

  function _createTopology(
    SessionPermissions memory sessionPerms
  ) internal returns (string memory topology) {
    topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    return topology;
  }

  function _createWallet(
    string memory topology
  ) internal returns (Stage1Module wallet, string memory config, bytes32 imageHash) {
    bytes32 sessionImageHash = PrimitivesRPC.sessionImageHash(vm, topology);

    string memory ce = string(
      abi.encodePacked("sapient:", vm.toString(sessionImageHash), ":", vm.toString(address(sessionManager)), ":1")
    );
    config = PrimitivesRPC.newConfig(vm, 1, 0, ce);
    imageHash = PrimitivesRPC.getImageHash(vm, config);
    wallet = Stage1Module(payable(factory.deploy(address(module), imageHash)));

    return (wallet, config, imageHash);
  }

  function _validExplicitSignature(
    Payload.Decoded memory payload,
    Vm.Wallet memory signer,
    string memory config,
    string memory topology,
    uint8[] memory permissionIdxs
  ) internal returns (bytes memory signature) {
    string[] memory callSignatures = new string[](payload.calls.length);
    for (uint256 i = 0; i < payload.calls.length; i++) {
      bytes32 callHash = SessionSig.hashCallWithReplayProtection(payload.calls[i], payload);
      console.log("Signing call", i);
      console.log("callHash");
      console.logBytes32(callHash);
      string memory sessionSignature = _signAndEncodeRSV(callHash, signer);
      callSignatures[i] = _explicitCallSignatureToJSON(permissionIdxs[i], sessionSignature);
    }
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = signer.addr;
    console.log("explicitSigners");
    console.log(explicitSigners[0]);
    address[] memory implicitSigners = new address[](0);
    bytes memory sessionSignatures =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures)));
    signature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, !payload.noChainId);
  }

}
