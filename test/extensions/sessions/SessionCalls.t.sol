// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm, console } from "forge-std/Test.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { Emitter } from "test/mocks/Emitter.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Calls } from "src/modules/Calls.sol";
import { ERC4337v07 } from "src/modules/ERC4337v07.sol";
import { Payload } from "src/modules/Payload.sol";
import { ISapient } from "src/modules/interfaces/ISapient.sol";

/// @notice Explicit session integration tests.
contract SessionCallsTest is SessionTestBase {

  Factory public factory;
  Stage1Module public module;
  SessionManager public sessionManager;
  Vm.Wallet public sessionWallet;
  Vm.Wallet public identityWallet;
  MockContract public target;

  function setUp() public {
    sessionWallet = vm.createWallet("session");
    identityWallet = vm.createWallet("identity");
    sessionManager = new SessionManager();
    factory = new Factory();
    module = new Stage1Module(address(factory), address(0));
    target = new MockContract();
  }

  function _validCall(Payload.Call memory call, bool callRevert) internal view returns (Payload.Call memory) {
    call.to = address(target);
    call.behaviorOnError = bound(call.behaviorOnError, 0, 2);
    call.value = bound(call.value, 0, 1 ether);
    call.data = abi.encodeWithSelector(MockContract.willRevert.selector, callRevert);
    call.gasLimit = bound(call.gasLimit, 0, 1); // Pass or fail due to gas limit

    // FIXME Remove. This is here to make it pass
    // call.behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    // call.onlyFallback = false;
    // call.data = abi.encodeWithSelector(MockContract.willRevert.selector, false);

    return call;
  }

  /// forge-config: default.fuzz.runs = 10_000
  function test_fuzzForSkippingIncrementCall(
    Payload.Call memory call0,
    Payload.Call memory call1,
    Payload.Call memory callIncrement,
    bool call0Revert,
    bool call1Revert
  ) public {
    Payload.Decoded memory payload = _buildPayload(3);
    // Fuzzes: Behavior, value, onlyFallback, gasLimit, contract call reverts
    payload.calls[0] = _validCall(call0, call0Revert);
    payload.calls[1] = _validCall(call1, call1Revert);

    // FIXME Remove. This is here to make it fail with abort on the second call
    // payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    // payload.calls[0].onlyFallback = false;
    // payload.calls[0].value = 1 ether;
    // payload.calls[1].onlyFallback = false;
    // payload.calls[1].behaviorOnError = Payload.BEHAVIOR_ABORT_ON_ERROR;
    // payload.calls[1].data = abi.encodeWithSelector(MockContract.willRevert.selector, true);

    uint256 totalValue = payload.calls[0].value + payload.calls[1].value;
    vm.assume(totalValue > 0); // Required to use an increment permission

    // Create the increment call
    UsageLimit[] memory usageLimits = new UsageLimit[](1);
    usageLimits[0] = UsageLimit({
      usageHash: keccak256(abi.encode(sessionWallet.addr, sessionManager.VALUE_TRACKING_ADDRESS())),
      usageAmount: totalValue
    });
    callIncrement = _validCall(callIncrement, false);
    callIncrement.to = address(sessionManager);
    callIncrement.data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, usageLimits);
    callIncrement.value = bound(callIncrement.value, 0, 1); // Reduce chance of increment having value. Known failure condition
    payload.calls[2] = callIncrement;

    // FIXME Remove. Fails as incrementCall aborts on low gas
    // payload.calls[2].behaviorOnError = Payload.BEHAVIOR_ABORT_ON_ERROR;
    // payload.calls[2].gasLimit = 1;

    // Create the valid explicit session
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: totalValue,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: address(target), rules: new ParameterRule[](0) });
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    bytes32 sessionImageHash = PrimitivesRPC.sessionImageHash(vm, topology);

    // Create the wallet config
    string memory config;
    {
      string memory ce = string(
        abi.encodePacked("sapient:", vm.toString(sessionImageHash), ":", vm.toString(address(sessionManager)), ":1")
      );
      config = PrimitivesRPC.newConfig(vm, 1, 0, ce);
    }
    bytes32 imageHash = PrimitivesRPC.getImageHash(vm, config);
    Stage1Module wallet = Stage1Module(payable(factory.deploy(address(module), imageHash)));

    // Fund the wallet
    vm.deal(address(wallet), totalValue + 1);

    // Sign the payload
    string[] memory callSignatures = new string[](3);
    for (uint256 i; i < 3; i++) {
      string memory sessionSignature =
        _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload.calls[i], payload), sessionWallet);
      callSignatures[i] = _explicitCallSignatureToJSON(0, sessionSignature);
    }
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory sessionSignatures =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures)));
    bytes memory encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, false);

    // Execute the payload
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);
    try wallet.execute(packedPayload, encodedSignature) {
      // If execution succeeds, check the increment is updated
      uint256 usageAmount = sessionManager.getLimitUsage(address(wallet), usageLimits[0].usageHash);
      assertEq(usageAmount, totalValue, "Usage should increment on successful execution");
      // It doesn't matter if the wallet spends funds or not
      // (error and IGNORE, error and IGNORE, increment) is ok
    } catch (bytes memory reason) {
      // If the execution reverts, check the wallet balance is unaffected
      bytes4 errorSelector = bytes4(reason);
      if (
        errorSelector == SessionErrors.InvalidBehavior.selector
          || errorSelector == SessionErrors.InvalidDelegateCall.selector
          || errorSelector == SessionErrors.InvalidValue.selector || errorSelector == Calls.NotEnoughGas.selector
          || errorSelector == Calls.Reverted.selector || errorSelector == MockContract.MockError.selector
      ) {
        // Should not spend funds or update usage limits
        assertEq(address(wallet).balance, totalValue + 1, "Wallet balance should not change");
        uint256 usageAmount = sessionManager.getLimitUsage(address(wallet), usageLimits[0].usageHash);
        assertEq(usageAmount, 0, "Usage should not increment");
      } else if (errorSelector == SessionErrors.InvalidLimitUsageIncrement.selector) {
        if (callIncrement.behaviorOnError != Payload.BEHAVIOR_REVERT_ON_ERROR || callIncrement.onlyFallback) {
          // Expected. Should not spend funds or update usage limits
          assertEq(address(wallet).balance, totalValue + 1, "Wallet balance should not change");
          uint256 usageAmount = sessionManager.getLimitUsage(address(wallet), usageLimits[0].usageHash);
          assertEq(usageAmount, 0, "Usage should not increment");
        } else {
          revert("Test not correctly fuzzed. This should always pass.");
        }
      } else {
        revert("Got an unexpected error. Update tests to handle this error.");
      }
    }
  }

}

contract MockContract {

  error MockError();

  function willRevert(
    bool doRevert
  ) public payable {
    if (doRevert) {
      revert MockError();
    }
  }

}
