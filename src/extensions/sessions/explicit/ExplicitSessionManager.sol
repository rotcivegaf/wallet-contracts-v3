// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../../../utils/LibBytes.sol";
import { LibBytesPointer } from "../../../utils/LibBytesPointer.sol";

import { Permission, UsageLimit } from "../Permission.sol";

import { ExplicitSessionSignature, IExplicitSessionManager, SessionPermissions } from "./IExplicitSessionManager.sol";

import { ISapient, Payload } from "../../../modules/interfaces/ISapient.sol";

import { PermissionValidator } from "../PermissionValidator.sol";
import { ExplicitSessionSig } from "./ExplicitSessionSig.sol";

using LibBytesPointer for bytes;
using LibBytes for bytes;

contract ExplicitSessionManager is ExplicitSessionSig, PermissionValidator, IExplicitSessionManager {

  // Special address used for tracking native token value limits
  address public constant VALUE_TRACKING_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

  /// @inheritdoc IExplicitSessionManager
  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external {
    for (uint256 i = 0; i < limits.length; i++) {
      limitUsage[limits[i].usageHash] += limits[i].usageAmount;
    }
  }

  /// @inheritdoc ISapient
  /// @dev The image hash derived from the global signer and session configuration
  function isValidSapientSignature(
    Payload.Decoded calldata payload,
    bytes calldata encodedSignature
  ) external view returns (bytes32) {
    // Recover the session manager signature
    ExplicitSessionSignature memory signature = _recoverSignature(payload, encodedSignature);

    // Validate the session using recovered permissions
    address wallet = msg.sender;
    _validateSession(wallet, payload, signature);

    // Return the permissions root as the image hash
    return signature.permissionsRoot;
  }

  /// @notice Validates the explicit session
  /// @param wallet The wallet's address
  /// @param payload The decoded payload containing calls
  /// @param signature The session signature data
  function _validateSession(
    address wallet,
    Payload.Decoded calldata payload,
    ExplicitSessionSignature memory signature
  ) internal view {
    SessionPermissions memory sessionPermissions = signature.sessionPermissions;

    // Check if session has expired
    if (sessionPermissions.deadline != 0 && block.timestamp > sessionPermissions.deadline) {
      revert SessionExpired(sessionPermissions.deadline);
    }

    // Validate calls and track usage
    bytes32 limitHashPrefix = keccak256(abi.encode(wallet, sessionPermissions.signer));
    (uint256 totalValueUsed, UsageLimit[] memory limits) =
      _validateCallsAndTrackUsage(limitHashPrefix, payload, signature);

    // Verify total value is within limit
    if (totalValueUsed != 0 && totalValueUsed > sessionPermissions.valueLimit) {
      revert InvalidValue();
    }

    // Verify limit usage increment call
    _verifyLimitUsageIncrement(payload, limits);
  }

  /// @notice Validates calls and tracks usage
  /// @param limitHashPrefix The hash prefix for the usage limits
  /// @param payload The decoded payload containing calls
  /// @param signature The session manager signature
  /// @return totalValueUsed The total value used
  /// @return limits The usage limits
  function _validateCallsAndTrackUsage(
    bytes32 limitHashPrefix,
    Payload.Decoded calldata payload,
    ExplicitSessionSignature memory signature
  ) private view returns (uint256 totalValueUsed, UsageLimit[] memory limits) {
    UsageLimit[][] memory allLimits = new UsageLimit[][](payload.calls.length + 1);
    uint256 limitIndex = 0;
    uint256 validArrays = 0;
    uint256 permissionIdx = 0;

    for (uint256 i = 0; i < payload.calls.length; i++) {
      Payload.Call calldata call = payload.calls[i];
      if (call.delegateCall) {
        // Delegate calls are not allowed
        revert InvalidDelegateCall();
      }

      if (call.to == address(this)) {
        // Skip validating self calls
        continue;
      }

      // Get the permission for the current call
      permissionIdx = signature.permissionIdxPerCall[i];
      if (permissionIdx >= signature.sessionPermissions.permissions.length) {
        revert MissingPermission(i);
      }

      if (call.value > 0) {
        // Track native token value
        totalValueUsed += call.value;
      }

      // Validate the permission for the current call
      (bool isValid, UsageLimit[] memory usageLimits) =
        validatePermission(signature.sessionPermissions.permissions[permissionIdx], call, limitHashPrefix);
      if (!isValid) {
        revert InvalidPermission(i);
      }

      // Track usage limits
      if (usageLimits.length > 0) {
        allLimits[validArrays] = usageLimits;
        limitIndex += usageLimits.length;
        validArrays++;
      }
    }

    // Create final arrays of exact size needed
    if (totalValueUsed == 0) {
      limits = new UsageLimit[](limitIndex);
    } else {
      limits = new UsageLimit[](limitIndex + 1);
      // Add the value tracking hash to the end
      limits[limitIndex] = UsageLimit({
        usageHash: keccak256(abi.encode(limitHashPrefix, VALUE_TRACKING_ADDRESS)),
        usageAmount: totalValueUsed
      });
    }

    // Flatten arrays
    limitIndex = 0;
    for (uint256 i = 0; i < validArrays; i++) {
      UsageLimit[] memory subLimits = allLimits[i];
      for (uint256 j = 0; j < subLimits.length; j++) {
        limits[limitIndex] = subLimits[j];
        limitIndex++;
      }
    }

    return (totalValueUsed, limits);
  }

  /// @notice Verifies the limit usage increment
  /// @param payload The decoded payload containing calls
  /// @param limits The usage limits
  /// @dev Reverts if the required increment call is missing or invalid
  function _verifyLimitUsageIncrement(Payload.Decoded calldata payload, UsageLimit[] memory limits) private view {
    // Limits call is only required if there are usage limits used
    if (limits.length > 0) {
      // Verify the last call is the increment call
      Payload.Call memory lastCall = payload.calls[payload.calls.length - 1];
      if (lastCall.to != address(this)) {
        revert MissingLimitUsageIncrement();
      }
      if (lastCall.behaviorOnError != Payload.BEHAVIOR_REVERT_ON_ERROR) {
        revert InvalidLimitUsageIncrement();
      }

      // Verify the increment call data
      bytes memory expectedData = abi.encodeWithSelector(this.incrementUsageLimit.selector, limits);
      bytes32 expectedDataHash = keccak256(expectedData);
      bytes32 actualDataHash = keccak256(lastCall.data);
      if (actualDataHash != expectedDataHash) {
        revert InvalidLimitUsageIncrement();
      }
    }
  }

  /// @notice Returns true if the contract implements the given interface
  /// @param interfaceId The interface identifier
  function supportsInterface(
    bytes4 interfaceId
  ) public pure returns (bool) {
    return interfaceId == type(ISapient).interfaceId || interfaceId == type(IExplicitSessionManager).interfaceId;
  }

}
