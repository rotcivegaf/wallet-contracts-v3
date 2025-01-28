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
  SessionManagerConfiguration,
  SessionManagerSignature,
  SessionPermissions
} from "../interfaces/ISessionManager.sol";
import { ISignalsImplicitMode } from "../interfaces/ISignalsImplicitMode.sol";

using LibBytesPointer for bytes;
using LibBytes for bytes;
using LibAttestation for Attestation;

contract SessionManager is PermissionValidator, ISessionManager {

  // Special address used for tracking native token value limits
  address public constant VALUE_TRACKING_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

  /// @inheritdoc ISessionManager
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
    address wallet = msg.sender;

    // Recover the session signer from the session signature
    bytes32 payloadHash = keccak256(abi.encode(payload));
    SessionManagerSignature memory signature = abi.decode(encodedSignature, (SessionManagerSignature));
    (bytes32 r, bytes32 s, uint8 v) = signature.sessionSignature.readMRSV(0);
    address recoveredPayloadSigner = ecrecover(payloadHash, v, r, s); // This is the session signer

    // Verify global signer's signature on the attestation
    bytes32 attestationHash = signature.attestation.toHash();
    (r, s, v) = signature.globalSignature.readMRSV(0);
    address recoveredGlobalSigner = ecrecover(attestationHash, v, r, s);

    // Validate the session
    _validateSession(wallet, signature, payload, recoveredPayloadSigner);

    // Generate and return imageHash
    return getImageHash(recoveredGlobalSigner, signature.configuration);
  }

  /// @notice Generates an image hash for the given configuration
  /// @param globalSigner The global signer address
  /// @param configuration The session configuration
  /// @return bytes32 The generated image hash
  function getImageHash(
    address globalSigner,
    SessionManagerConfiguration memory configuration
  ) public pure returns (bytes32) {
    return keccak256(abi.encode(globalSigner, configuration));
  }

  /// @notice Routes session validation to either implicit or explicit mode
  /// @param wallet The wallet's address
  /// @param signature The session signature data
  /// @param payload The decoded payload containing calls
  /// @param sessionSigner The signer for the current session
  function _validateSession(
    address wallet,
    SessionManagerSignature memory signature,
    Payload.Decoded calldata payload,
    address sessionSigner
  ) internal view {
    if (signature.isImplicit) {
      _validateImplicitMode(wallet, signature, payload, sessionSigner);
    } else {
      _validateExplicitMode(wallet, signature, payload, sessionSigner);
    }
  }

  /// @notice Validates a session in explicit mode
  /// @param wallet The wallet's address
  /// @param signature The session signature data
  /// @param payload The decoded payload containing calls
  /// @param sessionSigner The signer for the current session
  function _validateExplicitMode(
    address wallet,
    SessionManagerSignature memory signature,
    Payload.Decoded calldata payload,
    address sessionSigner
  ) internal view {
    // Get permissions for the signer
    SessionPermissions memory signerPermissions =
      _findSignerPermissions(signature.configuration.sessionPermissions, sessionSigner);

    // Check if session has expired
    if (signerPermissions.deadline != 0 && block.timestamp > signerPermissions.deadline) {
      revert SessionExpired(sessionSigner, signerPermissions.deadline);
    }

    // Validate calls and track usage
    bytes32 limitHashPrefix = keccak256(abi.encode(wallet, sessionSigner));
    (uint256 totalValueUsed, UsageLimit[] memory limits) = _validateCallsAndTrackUsage(
      limitHashPrefix, payload, signerPermissions.permissions, signature.permissionIdxPerCall
    );

    // Verify total value is within limit
    if (totalValueUsed != 0 && totalValueUsed > signerPermissions.valueLimit) {
      revert InvalidValue();
    }

    // Verify limit usage increment call
    _verifyLimitUsageIncrement(payload, limits);
  }

  /// @notice Finds the permissions for the given signer
  /// @param sessionPermissions The array of session permissions
  /// @param sessionSigner The signer for the current session
  /// @return signerPermissions The recovered permissions for the signer
  function _findSignerPermissions(
    SessionPermissions[] memory sessionPermissions,
    address sessionSigner
  ) private pure returns (SessionPermissions memory signerPermissions) {
    uint256 left = 0;
    uint256 right = sessionPermissions.length - 1;

    while (left <= right) {
      uint256 mid = left + (right - left) / 2;
      address currentSigner = sessionPermissions[mid].signer;
      if (currentSigner == sessionSigner) {
        return sessionPermissions[mid];
      } else if (currentSigner < sessionSigner) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }
    // Fail out if the signer is not found
    revert MissingPermissions(sessionSigner);
  }

  // 🤢
  struct ValidateCallsAndTrackUsageParams {
    UsageLimit[][] allLimits;
    uint256 limitIndex;
    uint256 validArrays;
    uint256 i;
    uint256 j;
    uint256 permissionIdx;
  }

  //FIXME This function has stack too deep issues
  /// @notice Validates calls and tracks usage
  /// @param limitHashPrefix The hash prefix for the usage limits
  /// @param payload The decoded payload containing calls
  /// @param permissions The permissions for the signer
  /// @param permissionIdxPerCall The index of the permission for each call
  /// @return totalValueUsed The total value used
  /// @return limits The usage limits
  function _validateCallsAndTrackUsage(
    bytes32 limitHashPrefix,
    Payload.Decoded calldata payload,
    Permission[] memory permissions,
    uint8[] memory permissionIdxPerCall
  ) private view returns (uint256 totalValueUsed, UsageLimit[] memory limits) {
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
        // Delegate calls are not allowed
        revert InvalidDelegateCall();
      }

      if (call.to == address(this)) {
        // Skip validating self calls
        continue;
      }

      // Get the permission for the current call
      params.permissionIdx = permissionIdxPerCall[params.i];
      if (params.permissionIdx >= permissions.length) {
        revert MissingPermission(params.i);
      }

      if (call.value > 0) {
        // Track native token value
        totalValueUsed += call.value;
      }

      // Validate the permission for the current call
      (bool isValid, UsageLimit[] memory usageLimits) =
        validatePermission(permissions[params.permissionIdx], call, limitHashPrefix);
      if (!isValid) {
        revert InvalidPermission(params.i);
      }

      // Track usage limits
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

  /// @notice Validates a session in implicit mode, checking blacklist and calling acceptImplicitRequest
  /// @param wallet The wallet's address
  /// @param signature The session signature data
  /// @param payload The decoded payload containing calls
  /// @param sessionSigner The signer for the current session
  function _validateImplicitMode(
    address wallet,
    SessionManagerSignature memory signature,
    Payload.Decoded calldata payload,
    address sessionSigner
  ) internal view {
    // Validate the session signer
    if (sessionSigner != signature.attestation.approvedSigner) {
      revert InvalidSessionSignature();
    }

    // Validate blacklist
    address[] memory blacklist = signature.configuration.implicitBlacklist;

    // Check each call's target address against blacklist
    for (uint256 i = 0; i < payload.calls.length; i++) {
      if (payload.calls[i].delegateCall) {
        // Delegate calls are not allowed
        revert InvalidDelegateCall();
      }
      if (_isAddressBlacklisted(payload.calls[i].to, blacklist)) {
        revert BlacklistedAddress(payload.calls[i].to);
      }
      // No value
      if (payload.calls[i].value > 0) {
        revert InvalidValue();
      }
    }

    bytes32 attestationMagic = signature.attestation.generateImplicitRequestMagic(wallet);
    bytes32 redirectUrlHash = keccak256(abi.encodePacked(signature.attestation.authData));

    for (uint256 i = 0; i < payload.calls.length; i++) {
      // Validate implicit mode
      bytes32 result = ISignalsImplicitMode(payload.calls[i].to).acceptImplicitRequest(
        wallet, signature.attestation, redirectUrlHash, payload.calls[i]
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
