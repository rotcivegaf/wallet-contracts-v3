// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../../utils/LibBytes.sol";
import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { Attestation, LibAttestation } from "../Attestation.sol";

import { PermissionValidator } from "../PermissionValidator.sol";
import { Permission, UsageLimit } from "../interfaces/IPermission.sol";
import { ISapient, Payload } from "../interfaces/ISapient.sol";
import {
  ISessionManager,
  SessionConfiguration,
  SessionConfigurationPermissions,
  SessionSignature
} from "../interfaces/ISessionManager.sol";
import { ISignalsImplicitMode } from "../interfaces/ISignalsImplicitMode.sol";

using LibBytesPointer for bytes;
using LibBytes for bytes;
using LibAttestation for Attestation;

//FIXME Find a way to use permissions across multiple sessions
// 1. Combine permissions from all available sessions? No, only "used" sessions

contract SessionManager is PermissionValidator, ISessionManager {

  // Special address used for tracking native token value limits
  address public constant VALUE_TRACKING_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

  /// @notice Increments the usage counter for multiple limit/session/target combinations
  /// @param limits Array of limit/session/target combinations
  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external {
    for (uint256 i = 0; i < limits.length; i++) {
      limitUsage[limits[i].usageHash] += limits[i].usageAmount;
    }
  }

  /// @notice Validates a Sapient signature and returns an image hash
  /// @param _payload The decoded payload containing calls to be executed
  /// @param _encodedSignature The encoded signature data
  /// @return bytes32 The image hash derived from the global signer and session configuration
  function isValidSapientSignature(
    Payload.Decoded calldata _payload,
    bytes calldata _encodedSignature
  ) external view returns (bytes32) {
    address wallet = msg.sender;

    // Recover the session signer from the session signature
    bytes32 payloadHash = keccak256(abi.encode(_payload));
    SessionSignature memory signature = abi.decode(_encodedSignature, (SessionSignature));
    (bytes32 r, bytes32 s, uint8 v) = signature.sessionSignature.readMRSV(0);
    address recoveredPayloadSigner = ecrecover(payloadHash, v, r, s); // This is the session signer

    // Verify global signer's signature on the attestation
    bytes32 attestationHash = signature.attestation.toHash();
    (r, s, v) = signature.globalSignature.readMRSV(0);
    address recoveredGlobalSigner = ecrecover(attestationHash, v, r, s);

    _validateSession(wallet, signature, _payload, recoveredPayloadSigner);

    // Generate and return imageHash
    return getImageHash(recoveredGlobalSigner, signature.sessionConfiguration);
  }

  /// @notice Generates an image hash for the given configuration
  /// @param globalSigner The global signer address
  /// @param sessionConfiguration The session configuration
  /// @return bytes32 The generated image hash
  function getImageHash(
    address globalSigner,
    SessionConfiguration memory sessionConfiguration
  ) public pure returns (bytes32) {
    return keccak256(abi.encode(globalSigner, sessionConfiguration));
  }

  /// @notice Routes session validation to either implicit or explicit mode
  /// @param wallet The user's wallet address
  /// @param signature The session signature data
  /// @param _payload The decoded payload containing calls
  /// @param recoveredPayloadSigner The address recovered from the payload signature
  function _validateSession(
    address wallet,
    SessionSignature memory signature,
    Payload.Decoded calldata _payload,
    address recoveredPayloadSigner
  ) internal view {
    if (signature.isImplicit) {
      _validateImplicitMode(wallet, signature, _payload, recoveredPayloadSigner);
    } else {
      _validateExplicitMode(wallet, signature, _payload, recoveredPayloadSigner);
    }
  }

  /// @notice Validates a session in explicit mode, checking permissions and usage limits
  /// @param wallet The user's wallet address
  /// @param signature The session signature data
  /// @param payload The decoded payload containing calls
  /// @param recoveredPayloadSigner The address recovered from the payload signature
  function _validateExplicitMode(
    address wallet,
    SessionSignature memory signature,
    Payload.Decoded calldata payload,
    address recoveredPayloadSigner
  ) internal view {
    // Get permissions for the signer
    (SessionConfigurationPermissions memory signerPermissions, Permission[] memory permissions) =
      _findSignerPermissions(signature.sessionConfiguration.sessionPermissions, recoveredPayloadSigner);

    // Check if session has expired
    if (signerPermissions.deadline != 0 && block.timestamp > signerPermissions.deadline) {
      revert SessionExpired(wallet, recoveredPayloadSigner);
    }

    // Validate calls and track usage
    bytes32 limitHashPrefix = keccak256(abi.encode(wallet, recoveredPayloadSigner));
    (uint256 totalValueUsed, UsageLimit[] memory limits) =
      _validateCallsAndTrackUsage(limitHashPrefix, payload, permissions, signature.permissionIdxPerCall);

    // Verify total value is within limit
    if (totalValueUsed > 0) {
      if (totalValueUsed > signerPermissions.valueLimit) {
        revert UsageLimitExceeded(wallet, VALUE_TRACKING_ADDRESS);
      }
    }

    // Verify limit usage increment call
    _verifyLimitUsageIncrement(payload, limits);
  }

  function _findSignerPermissions(
    SessionConfigurationPermissions[] memory sessionPermissions,
    address recoveredPayloadSigner
  ) private pure returns (SessionConfigurationPermissions memory signerPermissions, Permission[] memory permissions) {
    uint256 left = 0;
    uint256 right = sessionPermissions.length - 1;

    while (left <= right) {
      uint256 mid = left + (right - left) / 2;
      address currentSigner = sessionPermissions[mid].signer;
      if (currentSigner == recoveredPayloadSigner) {
        return (sessionPermissions[mid], sessionPermissions[mid].permissions);
      } else if (currentSigner < recoveredPayloadSigner) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }
    revert InvalidSessionSignature();
  }

  struct ValidateCallsAndTrackUsageParams {
    UsageLimit[][] allLimits;
    uint256 limitIndex;
    uint256 validArrays;
    uint256 i;
    uint256 j;
    uint256 permissionIdx;
  }

  //FIXME This function has stack too deep issues
  function _validateCallsAndTrackUsage(
    bytes32 limitHashPrefix,
    Payload.Decoded calldata payload,
    Permission[] memory permissions,
    uint8[] memory permissionIdxPerCall
  ) private view returns (uint256 totalValueUsed, UsageLimit[] memory limits) {
    // Create arrays to store all usage limits
    ValidateCallsAndTrackUsageParams memory params = ValidateCallsAndTrackUsageParams({
      allLimits: new UsageLimit[][](payload.calls.length + 1),
      limitIndex: 0,
      validArrays: 0,
      i: 0,
      j: 0,
      permissionIdx: 0
    });

    for (params.i = 0; params.i < payload.calls.length; params.i++) {
      Payload.Call calldata call = payload.calls[params.i];
      if (call.delegateCall) {
        revert InvalidDelegateCall();
      }

      if (call.to == address(this)) {
        continue;
      }

      if (call.value > 0) {
        totalValueUsed += call.value;
      }

      params.permissionIdx = permissionIdxPerCall[params.i];
      if (params.permissionIdx >= permissions.length) {
        revert MissingPermission(call.to, bytes4(call.data));
      }

      (bool isValid, UsageLimit[] memory usageLimits) =
        validatePermission(permissions[params.permissionIdx], call, limitHashPrefix);
      if (!isValid) {
        revert InvalidPermission(call.to, bytes4(call.data));
      }

      if (usageLimits.length > 0) {
        params.allLimits[params.validArrays] = usageLimits;
        params.limitIndex += usageLimits.length;
        params.validArrays++;
      }
    }

    // Create final arrays of exact size needed
    if (totalValueUsed == 0) {
      limits = new UsageLimit[](params.limitIndex);
    } else {
      limits = new UsageLimit[](params.limitIndex + 1);
      // Add the value tracking hash to the end
      limits[params.limitIndex] = UsageLimit({
        usageHash: keccak256(abi.encode(limitHashPrefix, VALUE_TRACKING_ADDRESS)),
        usageAmount: totalValueUsed
      });
    }

    // Flatten arrays
    params.limitIndex = 0;
    for (params.i = 0; params.i < params.validArrays; params.i++) {
      UsageLimit[] memory subLimits = params.allLimits[params.i];
      for (params.j = 0; params.j < subLimits.length; params.j++) {
        limits[params.limitIndex] = subLimits[params.j];
        params.limitIndex++;
      }
    }

    return (totalValueUsed, limits);
  }

  function _verifyLimitUsageIncrement(Payload.Decoded calldata _payload, UsageLimit[] memory limits) private view {
    if (limits.length > 0) {
      Payload.Call memory lastCall = _payload.calls[_payload.calls.length - 1];
      if (lastCall.to != address(this)) {
        revert MissingLimitUsageIncrement();
      }
      if (lastCall.behaviorOnError != Payload.BEHAVIOR_REVERT_ON_ERROR) {
        revert InvalidLimitUsageIncrement();
      }

      bytes memory expectedData = abi.encodeWithSelector(this.incrementUsageLimit.selector, limits);
      bytes32 expectedDataHash = keccak256(expectedData);
      bytes32 actualDataHash = keccak256(lastCall.data);
      if (actualDataHash != expectedDataHash) {
        revert InvalidLimitUsageIncrement();
      }
    }
  }

  /// @notice Validates a session in implicit mode, checking blacklist and calling acceptImplicitRequest
  /// @param wallet The user's wallet address
  /// @param signature The session signature data
  /// @param _payload The decoded payload containing calls
  /// @param recoveredPayloadSigner The address recovered from the payload signature
  function _validateImplicitMode(
    address wallet,
    SessionSignature memory signature,
    Payload.Decoded calldata _payload,
    address recoveredPayloadSigner
  ) internal view {
    // Validate the session signer
    if (recoveredPayloadSigner != signature.attestation._approvedSigner) {
      revert InvalidSessionSignature();
    }

    // Validate blacklist
    address[] memory blacklist = signature.sessionConfiguration.implicitBlacklist;

    // Check each call's target address against blacklist
    for (uint256 i = 0; i < _payload.calls.length; i++) {
      if (_payload.calls[i].delegateCall) {
        // Delegate calls are not allowed
        revert InvalidDelegateCall();
      }
      if (_isAddressBlacklisted(_payload.calls[i].to, blacklist)) {
        revert BlacklistedAddress(wallet, _payload.calls[i].to);
      }
      // No value
      if (_payload.calls[i].value > 0) {
        revert InvalidValue();
      }
    }

    bytes32 attestationMagic = signature.attestation.generateImplicitRequestMagic(wallet);
    bytes32 redirectUrlHash = keccak256(abi.encodePacked(signature.attestation._authData));

    for (uint256 i = 0; i < _payload.calls.length; i++) {
      // Validate implicit mode
      bytes32 result = ISignalsImplicitMode(_payload.calls[i].to).acceptImplicitRequest(
        wallet, signature.attestation, redirectUrlHash, _payload.calls[i]
      );
      if (result != attestationMagic) {
        revert InvalidImplicitResult();
      }
    }
  }

  /// @notice Checks if an address is in the blacklist using binary search
  /// @param target The address to check
  /// @param blacklist The sorted array of blacklisted addresses
  /// @return bool True if the address is blacklisted, false otherwise
  function _isAddressBlacklisted(address target, address[] memory blacklist) internal pure returns (bool) {
    int256 left = 0;
    int256 right = int256(blacklist.length) - 1;

    while (left <= right) {
      int256 mid = left + (right - left) / 2;
      address currentAddress = blacklist[uint256(mid)];

      if (currentAddress == target) {
        return true;
      } else if (currentAddress < target) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }

    return false;
  }

  /// @notice Returns true if the contract implements the given interface
  /// @param interfaceId The interface identifier
  function supportsInterface(
    bytes4 interfaceId
  ) public pure returns (bool) {
    return interfaceId == type(ISapient).interfaceId || interfaceId == type(ISessionManager).interfaceId;
  }

}
