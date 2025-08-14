// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { Emitter } from "test/mocks/Emitter.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Payload } from "src/modules/Payload.sol";
import { ISapient } from "src/modules/interfaces/ISapient.sol";

contract SessionManagerTest is SessionTestBase {

  SessionManager public sessionManager;
  address public explicitTarget;
  Vm.Wallet public sessionWallet;
  Vm.Wallet public identityWallet;
  Emitter public emitter;

  function setUp() public {
    sessionManager = new SessionManager();
    sessionWallet = vm.createWallet("session");
    identityWallet = vm.createWallet("identity");
    explicitTarget = address(0xBEEF);
    emitter = new Emitter();
  }

  /// @notice Valid explicit session test.
  function testValidExplicitSessionSignature(
    bytes4 selector,
    uint256 param,
    uint256 value,
    address explicitTarget2,
    bool useChainId
  ) public {
    vm.assume(explicitTarget != explicitTarget2);
    vm.assume(value > 0);
    vm.assume(param > 0);
    bytes memory callData = abi.encodeWithSelector(selector, param);

    // --- Session Permissions ---
    // Create a SessionPermissions struct granting permission for calls to explicitTarget.
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: useChainId ? block.chainid : 0,
      valueLimit: value,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](2)
    });
    // Permission with an empty rules set allows all calls to the target.
    ParameterRule[] memory rules = new ParameterRule[](2);
    // Rules for explicitTarget in call 0.
    rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(selector)) << 224),
      offset: 0,
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });
    rules[1] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.LESS_THAN_OR_EQUAL,
      value: bytes32(param),
      offset: 4, // offset the param (selector is 4 bytes)
      mask: bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: rules });
    sessionPerms.permissions[1] = Permission({ target: explicitTarget2, rules: new ParameterRule[](0) }); // Unlimited access

    // Build a payload with two calls:
    //   Call 0: call not requiring incrementUsageLimit
    //   Call 1: call requiring incrementUsageLimit
    //   Call 2: the required incrementUsageLimit call (self–call)
    Payload.Decoded memory payload = _buildPayload(3);

    // --- Explicit Call 1 ---
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: value,
      data: callData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Explicit Call 2 ---
    payload.calls[1] = Payload.Call({
      to: explicitTarget2,
      value: 0,
      data: callData, // Reuse this because permission for this target is open
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Increment Usage Limit ---
    {
      UsageLimit[] memory limits = new UsageLimit[](2);
      limits[0] = UsageLimit({
        usageHash: keccak256(abi.encode(sessionWallet.addr, sessionPerms.permissions[0], uint256(1))),
        usageAmount: param
      });
      limits[1] =
        UsageLimit({ usageHash: keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS)), usageAmount: value });
      payload.calls[2] = Payload.Call({
        to: address(sessionManager),
        value: 0,
        data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits),
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    uint8[] memory permissionIdxs = new uint8[](3);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 1; // Call 1
    permissionIdxs[2] = 0; // Call 2

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.prank(sessionWallet.addr);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  function testInvalidPayloadKindReverts() public {
    Payload.Decoded memory payload;
    bytes memory encodedSig;

    payload.kind = Payload.KIND_MESSAGE;
    vm.expectRevert(SessionManager.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);

    payload.kind = Payload.KIND_CONFIG_UPDATE;
    vm.expectRevert(SessionManager.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);

    payload.kind = Payload.KIND_DIGEST;
    vm.expectRevert(SessionManager.InvalidPayloadKind.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  function testInvalidCallsLengthReverts() public {
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    bytes memory encodedSig;

    vm.expectRevert(SessionManager.InvalidCallsLength.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that a call using delegateCall reverts.
  function testInvalidDelegateCallReverts(Attestation memory attestation, bytes memory data) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

    // Build a payload with one call that erroneously uses delegateCall.
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: data,
      gasLimit: 0,
      delegateCall: true, // invalid
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    vm.expectRevert(SessionErrors.InvalidDelegateCall.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that a self–call with nonzero value reverts with InvalidSelfCall.
  function testInvalidSelfCallReverts() public {
    // Build a payload with two calls:
    //   Call 0: valid explicit call.
    //   Call 1: self–call (incrementUsageLimit) with nonzero value (invalid).
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // --- Explicit Call (Call 0) ---
    bytes memory explicitCallData = abi.encodeWithSelector(0x12345678, uint256(42));
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: explicitCallData,
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // --- Self Call (Call 1) ---
    // Intentionally set nonzero value.
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 1, // nonzero -> should revert
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions for call 0.
    SessionPermissions memory sessionPerms;
    sessionPerms.signer = sessionWallet.addr;
    sessionPerms.valueLimit = 0;
    sessionPerms.deadline = uint64(block.timestamp + 1 days);
    sessionPerms.permissions = new Permission[](1);
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](1) });
    sessionPerms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(0x12345678)) << 224),
      offset: 0,
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });

    uint8[] memory permissionIdxs = new uint8[](2);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1

    (, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.expectRevert(SessionErrors.InvalidSelfCall.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Valid implicit session test.
  function testValidImplicitSessionSignature(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

    // Build a payload with one call for implicit session.
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: address(emitter),
      value: 0,
      data: abi.encodeWithSelector(Emitter.implicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (bytes32 imageHash, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    vm.prank(sessionWallet.addr);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that calls with onlyFallback = true are allowed
  function testOnlyFallbackCallsAllowed() public {
    // Build a payload with one call that has onlyFallback = true
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(emitter), // Use emitter instead of explicitTarget for implicit sessions
      value: 0,
      data: abi.encodeWithSelector(Emitter.implicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (bytes32 imageHash, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that calls with BEHAVIOR_IGNORE_ERROR are allowed
  function testBehaviorIgnoreErrorCallsAllowed() public {
    // Build a payload with one call that has BEHAVIOR_IGNORE_ERROR
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: address(emitter), // Use emitter instead of explicitTarget for implicit sessions
      value: 0,
      data: abi.encodeWithSelector(Emitter.implicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });

    (bytes32 imageHash, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that calls with BEHAVIOR_ABORT_ON_ERROR will revert with InvalidBehavior
  function testBehaviorAbortOnErrorCallsRevert() public {
    // Build a payload with one call that has BEHAVIOR_ABORT_ON_ERROR
    uint256 callCount = 1;
    Payload.Decoded memory payload = _buildPayload(callCount);
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: abi.encodeWithSelector(0x12345678, uint256(42)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_ABORT_ON_ERROR // This should revert
     });

    (, bytes memory encodedSig) = _validImplicitSessionSignature(payload);

    vm.expectRevert(SessionErrors.InvalidBehavior.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that calls with onlyFallback = true in explicit sessions are allowed
  function testExplicitSessionOnlyFallbackAllowed() public {
    // Build a payload with two calls: explicit call + increment call
    Payload.Decoded memory payload = _buildPayload(2);

    // First call with onlyFallback = true (should be allowed)
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: abi.encodeWithSelector(0x12345678, uint256(42)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Second call (increment call)
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](2);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.prank(sessionWallet.addr);
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that the increment call cannot have onlyFallback = true
  function testIncrementCallOnlyFallbackReverts() public {
    // Build a payload with two calls: explicit call + increment call with onlyFallback
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // First call (valid explicit call that will use usage limits)
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 1, // Use some value to trigger usage tracking
      data: abi.encodeWithSelector(0x12345678, uint256(42)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Second call (increment call with onlyFallback = true - should revert)
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](1)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true, // This should cause the increment call to be skipped
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions with value limit to trigger usage tracking
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 1, // Set value limit to trigger usage tracking
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](2);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1

    (, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that calls with BEHAVIOR_IGNORE_ERROR in explicit sessions are allowed
  function testExplicitSessionBehaviorIgnoreErrorAllowed() public {
    // Build a payload with two calls: explicit call with IGNORE_ERROR + increment call
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // First call with BEHAVIOR_IGNORE_ERROR (should be allowed)
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: abi.encodeWithSelector(0x12345678, uint256(42)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });

    // Second call (increment call)
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](2);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that calls with BEHAVIOR_ABORT_ON_ERROR in explicit sessions revert
  function testExplicitSessionBehaviorAbortOnErrorReverts() public {
    // Build a payload with two calls: explicit call with ABORT_ON_ERROR + increment call
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // First call with BEHAVIOR_ABORT_ON_ERROR (should revert)
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: abi.encodeWithSelector(0x12345678, uint256(42)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_ABORT_ON_ERROR // This should revert
     });

    // Second call (increment call)
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](2);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1

    (, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    vm.expectRevert(SessionErrors.InvalidBehavior.selector);
    sessionManager.recoverSapientSignature(payload, encodedSig);
  }

  /// @notice Test that mixed flags in the same payload work correctly
  function testMixedFlagsAllowed() public {
    // Build a payload with three calls: normal + onlyFallback + increment call
    uint256 callCount = 3;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // First call (normal)
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: abi.encodeWithSelector(0x12345678, uint256(42)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Second call with onlyFallback (should be allowed)
    payload.calls[1] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: abi.encodeWithSelector(0x87654321, uint256(24)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: true, // This should be allowed
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Third call (increment call)
    payload.calls[2] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](callCount);

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    // This should succeed since the mixed flags are allowed
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  /// @notice Test that valid linear execution still works
  function testValidLinearExecution() public {
    // Build a payload with two calls: explicit call + increment call (both with valid flags)
    uint256 callCount = 2;
    Payload.Decoded memory payload = _buildPayload(callCount);

    // First call (normal explicit call)
    payload.calls[0] = Payload.Call({
      to: explicitTarget,
      value: 0,
      data: abi.encodeWithSelector(0x12345678, uint256(42)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR // Valid behavior
     });

    // Second call (increment call with valid flags)
    payload.calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, new UsageLimit[](0)),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false, // Valid flag
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR // Valid behavior
     });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: explicitTarget, rules: new ParameterRule[](0) });

    uint8[] memory permissionIdxs = new uint8[](2);
    permissionIdxs[0] = 0; // Call 0
    permissionIdxs[1] = 0; // Call 1

    (bytes32 imageHash, bytes memory encodedSig) = _validExplicitSessionSignature(payload, sessionPerms, permissionIdxs);

    // This should succeed since all flags are valid for linear execution
    bytes32 actualImageHash = sessionManager.recoverSapientSignature(payload, encodedSig);
    assertEq(imageHash, actualImageHash);
  }

  // ============================================================================
  // HELPER FUNCTIONS
  // ============================================================================

  /// @notice Create a valid attestation for testing
  function _createValidAttestation() internal view returns (Attestation memory) {
    Attestation memory attestation;
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com";
    attestation.authData.issuedAt = uint64(block.timestamp);
    return attestation;
  }

  function _validImplicitSessionSignature(
    Payload.Decoded memory payload
  ) internal returns (bytes32 imageHash, bytes memory encodedSig) {
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    imageHash = PrimitivesRPC.sessionImageHash(vm, topology);

    uint256 callCount = payload.calls.length;
    string[] memory callSignatures = new string[](callCount);
    Attestation memory attestation = _createValidAttestation();
    for (uint256 i; i < callCount; i++) {
      callSignatures[i] = _createImplicitCallSignature(payload, i, sessionWallet, identityWallet, attestation);
    }

    address[] memory explicitSigners = new address[](0);
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    return (imageHash, encodedSig);
  }

  function _validExplicitSessionSignature(
    Payload.Decoded memory payload,
    SessionPermissions memory sessionPerms,
    uint8[] memory permissionIdxs
  ) internal returns (bytes32 imageHash, bytes memory encodedSig) {
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    imageHash = PrimitivesRPC.sessionImageHash(vm, topology);

    uint256 callCount = payload.calls.length;
    string[] memory callSignatures = new string[](callCount);
    for (uint256 i; i < callCount; i++) {
      string memory sessionSignature =
        _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload.calls[i], payload), sessionWallet);
      callSignatures[i] = _explicitCallSignatureToJSON(permissionIdxs[i], sessionSignature);
    }

    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

    return (imageHash, encodedSig);
  }

}
