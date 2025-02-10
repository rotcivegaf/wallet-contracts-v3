// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ParameterOperation, ParameterRule, Permission, UsageLimit } from "src/extensions/sessions/Permission.sol";
import {
  ExplicitSessionSignature,
  IExplicitSessionManager,
  IExplicitSessionManagerSignals,
  SessionPermissions
} from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { ISapient, Payload } from "src/modules/interfaces/ISapient.sol";
import { ExplicitSessionManager } from "src/extensions/sessions/explicit/ExplicitSessionManager.sol";

import { ERC20, MockERC20 } from "../../../mocks/MockERC20.sol";
import { AdvTest } from "../../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract MockExplicitSessionManager is ExplicitSessionManager {

  function validateCallsAndTrackUsage(
    bytes32 limitHashPrefix,
    Payload.Decoded calldata payload,
    ExplicitSessionSignature memory signature
  ) external view returns (uint256 totalValueUsed, UsageLimit[] memory limits) {
    return _validateCallsAndTrackUsage(limitHashPrefix, payload, signature);
  }

  function publicVerifyLimitUsageIncrement(Payload.Decoded calldata payload, UsageLimit[] memory limits) external view {
    _verifyLimitUsageIncrement(payload, limits);
  }

  function publicValidateSession(
    address wallet,
    Payload.Decoded calldata payload,
    ExplicitSessionSignature memory signature
  ) external view {
    _validateSession(wallet, payload, signature);
  }

  // Expose the internal usage mapping for testing.
  function getUsage(
    bytes32 hash
  ) external view returns (uint256) {
    return limitUsage[hash];
  }

}

contract ExplicitSessionManagerTest is AdvTest, IExplicitSessionManagerSignals {

  MockExplicitSessionManager public sessionManager;
  uint256 public sessionPk;
  address public sessionAddr;
  MockERC20 public erc20;

  function setUp() public {
    sessionManager = new MockExplicitSessionManager();
  }

  modifier withSession(
    uint256 _sessionPk
  ) {
    sessionPk = boundPk(_sessionPk);
    sessionAddr = vm.addr(sessionPk);
    vm.label(sessionAddr, "sessionAddr");
    _;
  }

  modifier withERC20() {
    erc20 = new MockERC20("MockERC20", "MOCK");
    erc20.mint(sessionAddr, 10 ether);
    _;
  }

  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(IExplicitSessionManager).interfaceId));
  }

  //────────────────────────────────────────────────────────────
  // ERC20 Transfer end-to-end test
  //────────────────────────────────────────────────────────────
  function test_erc20Transfer(
    uint256 _sessionPk,
    uint256 amount,
    uint256 maxAmount
  ) public withSession(_sessionPk) withERC20 {
    maxAmount = bound(maxAmount, 2, 10 ether);
    amount = bound(amount, 1, maxAmount - 1);

    SessionPermissions memory sessionPermissions = SessionPermissions({
      signer: sessionAddr,
      valueLimit: 0, // no native token limit
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    sessionPermissions.permissions[0] = Permission({ target: address(erc20), rules: new ParameterRule[](2) });
    sessionPermissions.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(ERC20.transfer.selector),
      offset: 0,
      mask: bytes32(bytes4(0xffffffff))
    });
    sessionPermissions.permissions[0].rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(maxAmount),
      offset: 36,
      mask: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    });

    ExplicitSessionSignature memory signature = ExplicitSessionSignature({
      permissionsRoot: bytes32(0),
      sessionPermissions: sessionPermissions,
      permissionIdxPerCall: new uint8[](1)
    });
    signature.permissionIdxPerCall[0] = 0;

    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: new Payload.Call[](1),
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    payloadData.calls[0] = Payload.Call({
      to: address(erc20),
      value: 0,
      data: abi.encodeWithSelector(ERC20.transfer.selector, address(this), amount),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });

    bytes32 limitHashPrefix = keccak256(abi.encode(address(this), sessionAddr));
    (uint256 totalValueUsed, UsageLimit[] memory limitsOut) =
      sessionManager.validateCallsAndTrackUsage(limitHashPrefix, payloadData, signature);
    assertEq(totalValueUsed, 0, "Total value used");
    assertEq(limitsOut.length, 1, "Limits length");
    assertEq(
      limitsOut[0].usageHash,
      keccak256(abi.encode(limitHashPrefix, sessionPermissions.permissions[0])),
      "Usage hash mismatch"
    );
    assertEq(limitsOut[0].usageAmount, amount, "Usage amount mismatch");
  }

  //────────────────────────────────────────────────────────────
  // Tests for _verifyLimitUsageIncrement
  //────────────────────────────────────────────────────────────
  function test_verifyLimitUsageIncrement_valid(
    uint256 usageAmount
  ) public view {
    usageAmount = bound(usageAmount, 1, 1000);
    UsageLimit[] memory limitsArr = new UsageLimit[](1);
    limitsArr[0] = UsageLimit({ usageHash: keccak256(abi.encode("test", uint256(1))), usageAmount: usageAmount });
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limitsArr),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    sessionManager.publicVerifyLimitUsageIncrement(payloadData, limitsArr);
  }

  function test_verifyLimitUsageIncrement_missingCall(
    uint256 _sessionPk,
    address wrongTarget
  ) public withSession(_sessionPk) {
    if (wrongTarget == address(sessionManager)) {
      wrongTarget = address(0x123);
    }
    UsageLimit[] memory limitsArr = new UsageLimit[](1);
    limitsArr[0] = UsageLimit({ usageHash: keccak256(abi.encode("test", uint256(1))), usageAmount: 100 });
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: wrongTarget,
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limitsArr),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    vm.expectRevert(abi.encodeWithSelector(MissingLimitUsageIncrement.selector));
    sessionManager.publicVerifyLimitUsageIncrement(payloadData, limitsArr);
  }

  function test_verifyLimitUsageIncrement_invalidBehavior(
    uint256 _sessionPk,
    uint8 flag
  ) public withSession(_sessionPk) {
    if (flag == Payload.BEHAVIOR_REVERT_ON_ERROR) {
      flag = 0;
    }
    UsageLimit[] memory limitsArr = new UsageLimit[](1);
    limitsArr[0] = UsageLimit({ usageHash: keccak256(abi.encode("test", uint256(1))), usageAmount: 100 });
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limitsArr),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: flag
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    vm.expectRevert(abi.encodeWithSelector(InvalidLimitUsageIncrement.selector));
    sessionManager.publicVerifyLimitUsageIncrement(payloadData, limitsArr);
  }

  function test_verifyLimitUsageIncrement_invalidData(
    uint256 _sessionPk,
    uint256 dataLength
  ) public withSession(_sessionPk) {
    dataLength = bound(dataLength, 0, 100);
    bytes memory invalidData = new bytes(dataLength);
    UsageLimit[] memory limitsArr = new UsageLimit[](1);
    limitsArr[0] = UsageLimit({ usageHash: keccak256(abi.encode("test", uint256(1))), usageAmount: 100 });
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: invalidData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    vm.expectRevert(abi.encodeWithSelector(InvalidLimitUsageIncrement.selector));
    sessionManager.publicVerifyLimitUsageIncrement(payloadData, limitsArr);
  }

  //────────────────────────────────────────────────────────────
  // Tests for _validateCallsAndTrackUsage
  //────────────────────────────────────────────────────────────
  function test_validateCallsAndTrackUsage_delegateCall(
    uint256 _sessionPk,
    uint256 transferAmount
  ) public withSession(_sessionPk) withERC20 {
    transferAmount = bound(transferAmount, 1, 1000);
    uint256 maxAmount = 1000;
    Permission memory permission = Permission({ target: address(erc20), rules: new ParameterRule[](2) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(ERC20.transfer.selector),
      offset: 0,
      mask: bytes32(bytes4(0xffffffff))
    });
    permission.rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(maxAmount),
      offset: 36,
      mask: bytes32(type(uint256).max)
    });
    SessionPermissions memory sessionPermissions = SessionPermissions({
      signer: sessionAddr,
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    sessionPermissions.permissions[0] = permission;
    ExplicitSessionSignature memory signature = ExplicitSessionSignature({
      permissionsRoot: bytes32(0),
      sessionPermissions: sessionPermissions,
      permissionIdxPerCall: new uint8[](1)
    });
    signature.permissionIdxPerCall[0] = 0;
    bytes memory callData = abi.encodeWithSelector(ERC20.transfer.selector, address(this), transferAmount);
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(erc20),
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: true,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    bytes32 limitHashPrefix = keccak256(abi.encode(address(this), sessionAddr));
    vm.expectRevert(abi.encodeWithSelector(InvalidDelegateCall.selector));
    sessionManager.validateCallsAndTrackUsage(limitHashPrefix, payloadData, signature);
  }

  //────────────────────────────────────────────────────────────
  // Tests for _validateSession
  //────────────────────────────────────────────────────────────
  function test_validateSession_valid(
    uint256 _sessionPk,
    uint256 transferAmount,
    uint256 maxAmount
  ) public withSession(_sessionPk) withERC20 {
    maxAmount = bound(maxAmount, 2, 10 ether);
    transferAmount = bound(transferAmount, 1, maxAmount - 1);

    SessionPermissions memory sessionPermissions = SessionPermissions({
      signer: sessionAddr,
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    sessionPermissions.permissions[0] = Permission({ target: address(erc20), rules: new ParameterRule[](2) });
    sessionPermissions.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(ERC20.transfer.selector),
      offset: 0,
      mask: bytes32(bytes4(0xffffffff))
    });
    sessionPermissions.permissions[0].rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(maxAmount),
      offset: 36,
      mask: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    });
    ExplicitSessionSignature memory signature = ExplicitSessionSignature({
      permissionsRoot: bytes32(0),
      sessionPermissions: sessionPermissions,
      permissionIdxPerCall: new uint8[](1)
    });
    signature.permissionIdxPerCall[0] = 0;

    // Calculate remaining so that cumulative usage stays under maxAmount.
    uint256 remaining = maxAmount - transferAmount;
    remaining = bound(remaining, 1, remaining);

    bytes32 limitHashPrefix = keccak256(abi.encode(address(this), sessionAddr));

    // First call.
    Payload.Decoded memory payload1 = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: new Payload.Call[](2),
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    payload1.calls[0] = Payload.Call({
      to: address(erc20),
      value: 0,
      data: abi.encodeWithSelector(ERC20.transfer.selector, address(this), transferAmount),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    payload1.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    (, UsageLimit[] memory limits1) = sessionManager.validateCallsAndTrackUsage(limitHashPrefix, payload1, signature);
    sessionManager.incrementUsageLimit(limits1);
    bytes32 usageHash = keccak256(abi.encode(limitHashPrefix, sessionPermissions.permissions[0]));
    assertEq(sessionManager.getUsage(usageHash), transferAmount, "First call usage not recorded");

    // Second call.
    Payload.Decoded memory payload2 = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: new Payload.Call[](2),
      space: 0,
      nonce: 1,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    payload2.calls[0] = Payload.Call({
      to: address(erc20),
      value: 0,
      data: abi.encodeWithSelector(ERC20.transfer.selector, address(this), remaining),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    payload2.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    (, UsageLimit[] memory limits2) = sessionManager.validateCallsAndTrackUsage(limitHashPrefix, payload2, signature);
    sessionManager.incrementUsageLimit(limits2);
    assertEq(sessionManager.getUsage(usageHash), transferAmount + remaining, "Cumulative usage incorrect");
  }

  //────────────────────────────────────────────────────────────
  // Tests for cumulative limit
  //────────────────────────────────────────────────────────────
  function test_multipleCallsOverCumulativeLimitFuzz(
    uint256 _sessionPk,
    uint256 amount1,
    uint256 amount2
  ) public withSession(_sessionPk) withERC20 {
    uint256 cumulativeLimit = 500;
    amount1 = bound(amount1, 1, cumulativeLimit - 1);
    amount2 = bound(amount2, cumulativeLimit - amount1 + 1, cumulativeLimit * 2);

    SessionPermissions memory sessionPermissions = SessionPermissions({
      signer: sessionAddr,
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    sessionPermissions.permissions[0] = Permission({ target: address(erc20), rules: new ParameterRule[](2) });
    sessionPermissions.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(ERC20.transfer.selector),
      offset: 0,
      mask: bytes32(bytes4(0xffffffff))
    });
    sessionPermissions.permissions[0].rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(cumulativeLimit),
      offset: 36,
      mask: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    });
    ExplicitSessionSignature memory signature = ExplicitSessionSignature({
      permissionsRoot: bytes32(0),
      sessionPermissions: sessionPermissions,
      permissionIdxPerCall: new uint8[](1)
    });
    signature.permissionIdxPerCall[0] = 0;
    bytes32 limitHashPrefix = keccak256(abi.encode(address(this), sessionAddr));
    bytes32 usageHash = keccak256(abi.encode(limitHashPrefix, sessionPermissions.permissions[0]));

    // First call: transfer amount1.
    Payload.Decoded memory payload1 = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: new Payload.Call[](2),
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    payload1.calls[0] = Payload.Call({
      to: address(erc20),
      value: 0,
      data: abi.encodeWithSelector(ERC20.transfer.selector, address(this), amount1),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    payload1.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    (, UsageLimit[] memory limits1) = sessionManager.validateCallsAndTrackUsage(limitHashPrefix, payload1, signature);
    sessionManager.incrementUsageLimit(limits1);
    assertEq(sessionManager.getUsage(usageHash), amount1, "First call usage not recorded");

    // Second call: transfer amount2 should revert.
    Payload.Decoded memory payload2 = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: new Payload.Call[](2),
      space: 0,
      nonce: 1,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    payload2.calls[0] = Payload.Call({
      to: address(erc20),
      value: 0,
      data: abi.encodeWithSelector(ERC20.transfer.selector, address(this), amount2),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    payload2.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    vm.expectRevert(abi.encodeWithSelector(InvalidPermission.selector, 0));
    sessionManager.validateCallsAndTrackUsage(limitHashPrefix, payload2, signature);
  }

  //────────────────────────────────────────────────────────────
  // Tests for expired session
  //────────────────────────────────────────────────────────────
  function test_validateSession_expired(
    uint256 _sessionPk,
    uint256 deadlineParam
  ) public withSession(_sessionPk) withERC20 {
    vm.warp(1000);
    uint256 deadline = bound(deadlineParam, 1, 999);
    uint256 maxAmount = 500;
    Permission memory permission = Permission({ target: address(erc20), rules: new ParameterRule[](2) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(ERC20.transfer.selector),
      offset: 0,
      mask: bytes32(bytes4(0xffffffff))
    });
    permission.rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(maxAmount),
      offset: 36,
      mask: bytes32(type(uint256).max)
    });
    SessionPermissions memory sessionPermissions =
      SessionPermissions({ signer: sessionAddr, valueLimit: 0, deadline: deadline, permissions: new Permission[](1) });
    sessionPermissions.permissions[0] = permission;
    ExplicitSessionSignature memory signature = ExplicitSessionSignature({
      permissionsRoot: bytes32(0),
      sessionPermissions: sessionPermissions,
      permissionIdxPerCall: new uint8[](0)
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: new Payload.Call[](0),
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    vm.expectRevert(abi.encodeWithSelector(SessionExpired.selector, deadline));
    sessionManager.publicValidateSession(address(this), payloadData, signature);
  }

  //────────────────────────────────────────────────────────────
  // Tests for value
  //────────────────────────────────────────────────────────────
  function test_validateSession_valueLimitExceeded(
    uint256 _sessionPk,
    uint256 nativeValue
  ) public withSession(_sessionPk) {
    nativeValue = bound(nativeValue, 401, 1000);
    Permission memory permission = Permission({ target: address(0xBEEF), rules: new ParameterRule[](0) });
    SessionPermissions memory sessionPermissions = SessionPermissions({
      signer: sessionAddr,
      valueLimit: 400,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    sessionPermissions.permissions[0] = permission;
    ExplicitSessionSignature memory signature = ExplicitSessionSignature({
      permissionsRoot: bytes32(0),
      sessionPermissions: sessionPermissions,
      permissionIdxPerCall: new uint8[](1)
    });
    signature.permissionIdxPerCall[0] = 0;
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(0xBEEF),
      value: nativeValue,
      data: "",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: 0
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    vm.expectRevert(abi.encodeWithSelector(InvalidValue.selector));
    sessionManager.publicValidateSession(address(this), payloadData, signature);
  }

  //────────────────────────────────────────────────────────────
  // Tests for limit usage
  //────────────────────────────────────────────────────────────
  function test_validateSession_missingLimitUsageIncrement(
    uint256 _sessionPk,
    uint256 transferAmount
  ) public withSession(_sessionPk) withERC20 {
    transferAmount = bound(transferAmount, 1, 499);
    uint256 maxAmount = 500;
    Permission memory permission = Permission({ target: address(erc20), rules: new ParameterRule[](2) });
    permission.rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(ERC20.transfer.selector),
      offset: 0,
      mask: bytes32(bytes4(0xffffffff))
    });
    permission.rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(maxAmount),
      offset: 36,
      mask: bytes32(type(uint256).max)
    });
    SessionPermissions memory sessionPermissions = SessionPermissions({
      signer: sessionAddr,
      valueLimit: 0,
      deadline: block.timestamp + 1 days,
      permissions: new Permission[](1)
    });
    sessionPermissions.permissions[0] = permission;
    ExplicitSessionSignature memory signature = ExplicitSessionSignature({
      permissionsRoot: bytes32(0),
      sessionPermissions: sessionPermissions,
      permissionIdxPerCall: new uint8[](1)
    });
    signature.permissionIdxPerCall[0] = 0;
    bytes memory callData = abi.encodeWithSelector(ERC20.transfer.selector, address(this), transferAmount);
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(erc20),
      value: 0,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    Payload.Decoded memory payloadData = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
    vm.expectRevert(abi.encodeWithSelector(MissingLimitUsageIncrement.selector));
    sessionManager.publicValidateSession(address(this), payloadData, signature);
  }

}
