// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Test.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { ExplicitSessionManager } from "src/extensions/sessions/explicit/ExplicitSessionManager.sol";
import { SessionPermissions, SessionUsageLimits } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Payload } from "src/modules/Payload.sol";

contract ExplicitSessionManagerTest is SessionTestBase {

  ExplicitSessionManagerHarness harness;
  address wallet;
  Vm.Wallet sessionWallet;
  // Constant for the value tracking address as defined in your ExplicitSessionManager.
  address constant VALUE_TRACKING_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
  bytes32 constant SELECTOR_MASK = bytes32(bytes4(0xffffffff));

  function setUp() public {
    harness = new ExplicitSessionManagerHarness();
    wallet = vm.createWallet("wallet").addr;
    sessionWallet = vm.createWallet("session");
  }

  /// @dev Test a valid explicit call.
  function testValidateExplicitCall_Succeeds(address target, bytes4 selector, bytes memory callData) public view {
    vm.assume(target != address(harness));
    // Build a payload with one call.
    Payload.Decoded memory payload = _buildPayload(1);
    // Prepend the selector to the call data.
    callData = abi.encodePacked(selector, callData);
    payload.calls[0] = Payload.Call({
      to: target,
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions with one Permission.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      valueLimit: 0, // no native token usage for this test
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    // Allow calls to the target if the selector matches..
    perms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(selector),
      offset: 0,
      mask: SELECTOR_MASK
    });

    // Prepare initial session usage limits.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    // Convert our single SessionPermissions into an array.
    SessionPermissions[] memory permsArr = _toArray(perms);

    // Call the internal explicit call validator.
    SessionUsageLimits memory newUsage = harness.validateExplicitCall(
      payload,
      0, // call index
      wallet,
      sessionWallet.addr,
      permsArr,
      0, // permission index
      usage
    );

    // Since the call value is 0, expect totalValueUsed to remain 0.
    assertEq(newUsage.totalValueUsed, 0, "totalValueUsed should be 0");
  }

  /// @dev Test that an explicit call with invalid call data reverts due to invalid permission.
  function testValidateExplicitCall_InvalidPermission() public {
    Payload.Decoded memory payload = _buildPayload(1);
    // Use call data that does not match the expected selector.
    bytes memory callData = hex"deadbeef";
    payload.calls[0] = Payload.Call({
      to: address(0xDEAD),
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create SessionPermissions expecting selector 0x12345678.
    SessionPermissions memory perms = SessionPermissions({
      signer: sessionWallet.addr,
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    perms.permissions[0] = Permission({ target: payload.calls[0].to, rules: new ParameterRule[](1) });
    perms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(bytes4(0x12345678)),
      offset: 0,
      mask: SELECTOR_MASK
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 0;

    SessionPermissions[] memory permsArr = _toArray(perms);

    // Expect a revert with the InvalidPermission error.
    vm.expectRevert(SessionErrors.InvalidPermission.selector);
    harness.validateExplicitCall(payload, 0, wallet, sessionWallet.addr, permsArr, 0, usage);
  }

  /// @dev Test that _validateLimitUsageIncrement succeeds when the increment call is properly constructed.
  function testValidateLimitUsageIncrement_Succeeds() public view {
    // Prepare a call that is intended to be the increment call.
    Payload.Call memory incCall = Payload.Call({
      to: address(harness), // must equal the harness address (the contract itself)
      value: 0,
      data: "", // will be filled with expected encoding
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Prepare session usage limits with a nonzero totalValueUsed.
    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0); // no extra limits for simplicity
    usage.totalValueUsed = 100;

    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    // Construct the expected usage increment.
    // Calculate the limit hash prefix as in the internal function.
    bytes32 limitHashPrefix = keccak256(abi.encode(wallet, sessionWallet.addr));
    UsageLimit memory expectedLimit = UsageLimit({
      usageHash: keccak256(abi.encode(limitHashPrefix, VALUE_TRACKING_ADDRESS)),
      usageAmount: usage.totalValueUsed
    });
    UsageLimit[] memory limitsArr = new UsageLimit[](1);
    limitsArr[0] = expectedLimit;

    // Encode the expected increment call data.
    bytes memory expectedData = abi.encodeWithSelector(harness.incrementUsageLimit.selector, limitsArr);
    incCall.data = expectedData;

    // This call should pass without revert.
    harness.validateLimitUsageIncrement(incCall, usageArr, wallet);
  }

  /// @dev Test that _validateLimitUsageIncrement reverts if the call target is incorrect.
  function testValidateLimitUsageIncrement_InvalidCall() public {
    // Prepare a call with an incorrect target.
    Payload.Call memory incCall = Payload.Call({
      to: address(0xDEAD), // wrong target
      value: 0,
      data: "invalid",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    SessionUsageLimits memory usage;
    usage.signer = sessionWallet.addr;
    usage.limits = new UsageLimit[](0);
    usage.totalValueUsed = 50;

    SessionUsageLimits[] memory usageArr = new SessionUsageLimits[](1);
    usageArr[0] = usage;

    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    harness.validateLimitUsageIncrement(incCall, usageArr, wallet);
  }

}

contract ExplicitSessionManagerHarness is ExplicitSessionManager {

  /// @notice Exposes the internal _validateExplicitCall function.
  function validateExplicitCall(
    Payload.Decoded calldata payload,
    uint256 callIdx,
    address wallet,
    address sessionWallet,
    SessionPermissions[] memory allSessionPermissions,
    uint8 permissionIdx,
    SessionUsageLimits memory sessionUsageLimits
  ) public view returns (SessionUsageLimits memory) {
    return _validateExplicitCall(
      payload, callIdx, wallet, sessionWallet, allSessionPermissions, permissionIdx, sessionUsageLimits
    );
  }

  /// @notice Exposes the internal _validateLimitUsageIncrement function.
  function validateLimitUsageIncrement(
    Payload.Call calldata call,
    SessionUsageLimits[] memory sessionUsageLimits,
    address wallet
  ) public view {
    _validateLimitUsageIncrement(call, sessionUsageLimits, wallet);
  }

}
