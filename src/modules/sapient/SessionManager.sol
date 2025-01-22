// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../../utils/LibBytes.sol";
import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { Attestation, LibAttestation } from "../Attestation.sol";
import { Permissions } from "../Permissions.sol";
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

contract SessionManager is ISessionManager {

  // Track usage per wallet/session/target
  mapping(bytes32 => uint256) private limitUsage;

  // Special address used for tracking native token value limits
  address public constant VALUE_TRACKING_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

  /// @notice Increments the usage counter for multiple limit/session/target combinations
  /// @param limitUsageHashes Array of hashes representing wallet/session/target combinations
  /// @param usageAmounts Array of amounts to increment each usage counter by
  function incrementLimitUsage(bytes32[] calldata limitUsageHashes, uint256[] calldata usageAmounts) external {
    for (uint256 i = 0; i < limitUsageHashes.length; i++) {
      limitUsage[limitUsageHashes[i]] += usageAmounts[i];
    }
  }

  /// @notice Generates a unique hash for tracking usage limits
  /// @param wallet The user's wallet address
  /// @param sessionAddress The session contract address
  /// @param targetAddress The target contract being called
  /// @return A unique hash combining the three parameters
  function getUsageHash(address wallet, address sessionAddress, address targetAddress) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(wallet, sessionAddress, targetAddress));
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
  /// @param _payload The decoded payload containing calls
  /// @param recoveredPayloadSigner The address recovered from the payload signature
  function _validateExplicitMode(
    address wallet,
    SessionSignature memory signature,
    Payload.Decoded calldata _payload,
    address recoveredPayloadSigner
  ) internal view {
    // Get permissions for the signer
    (SessionConfigurationPermissions memory signerPermissions, Permissions.EncodedPermission[] memory permissions) =
      _findSignerPermissions(signature.sessionConfiguration.sessionPermissions, recoveredPayloadSigner);

    // Check if session has expired
    if (signerPermissions.deadline != 0 && block.timestamp > signerPermissions.deadline) {
      revert SessionExpired(wallet, recoveredPayloadSigner);
    }

    // Validate calls and track usage
    (uint256 totalValueUsed, uint256[] memory totalUsage) =
      _validateCallsAndTrackUsage(wallet, _payload, permissions, signature.permissionIdxPerCall);

    // Verify total value is within limit
    if (totalValueUsed > 0) {
      if (totalValueUsed > signerPermissions.valueLimit) {
        revert PermissionLimitExceeded(wallet, VALUE_TRACKING_ADDRESS);
      }
    }

    // Verify limit usage increment call
    _verifyLimitUsageIncrement(wallet, _payload, permissions, totalUsage, totalValueUsed, recoveredPayloadSigner);
  }

  function _findSignerPermissions(
    SessionConfigurationPermissions[] memory sessionPermissions,
    address recoveredPayloadSigner
  )
    private
    pure
    returns (
      SessionConfigurationPermissions memory signerPermissions,
      Permissions.EncodedPermission[] memory permissions
    )
  {
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

  function _validateCallsAndTrackUsage(
    address wallet,
    Payload.Decoded calldata _payload,
    Permissions.EncodedPermission[] memory permissions,
    uint8[] memory permissionIdxPerCall
  ) private view returns (uint256 totalValueUsed, uint256[] memory totalUsage) {
    totalUsage = new uint256[](permissions.length);
    totalValueUsed = 0;

    for (uint256 i = 0; i < _payload.calls.length; i++) {
      if (_payload.calls[i].delegateCall) {
        revert InvalidDelegateCall();
      }

      if (_payload.calls[i].to == address(this)) {
        // No validation for calls to this contract
        continue;
      }

      if (_payload.calls[i].value > 0) {
        uint256 newTotal = totalValueUsed + _payload.calls[i].value;
        totalValueUsed = newTotal;
      }

      uint256 permissionIdx = permissionIdxPerCall[i];
      if (permissionIdx >= permissions.length) {
        revert MissingPermission(wallet, _payload.calls[i].to, bytes4(_payload.calls[i].data));
      }

      Permissions.EncodedPermission memory permission = permissions[permissionIdx];
      if (!Permissions.validatePermission(permission, _payload.calls[i])) {
        revert MissingPermission(wallet, _payload.calls[i].to, bytes4(_payload.calls[i].data));
      }

      if (_hasLimit(permission.pType)) {
        uint256 usageAmount = Permissions.getUsageAmount(permission, _payload.calls[i]);
        uint256 newUsage = totalUsage[permissionIdx] + usageAmount;
        totalUsage[permissionIdx] = newUsage;
      }
    }
  }

  function _verifyLimitUsageIncrement(
    address wallet,
    Payload.Decoded calldata _payload,
    Permissions.EncodedPermission[] memory permissions,
    uint256[] memory totalUsage,
    uint256 totalValueUsed,
    address recoveredPayloadSigner
  ) private view {
    uint256 limitUsageCount = 0;
    bytes32[] memory expectedLimitUsageHashes = new bytes32[](permissions.length + (totalValueUsed > 0 ? 1 : 0));
    uint256[] memory expectedUsageAmounts = new uint256[](permissions.length + (totalValueUsed > 0 ? 1 : 0));

    if (totalValueUsed > 0) {
      expectedLimitUsageHashes[limitUsageCount] = getUsageHash(wallet, recoveredPayloadSigner, VALUE_TRACKING_ADDRESS);
      expectedUsageAmounts[limitUsageCount] = totalValueUsed;
      limitUsageCount++;
    }

    for (uint256 i = 0; i < totalUsage.length; i++) {
      if (totalUsage[i] > 0) {
        Permissions.EncodedPermission memory permission = permissions[i];
        uint256 limit = Permissions.getLimit(permission);
        if (limit > 0 && totalUsage[i] > limit) {
          revert PermissionLimitExceeded(wallet, _payload.calls[0].to);
        }
        expectedLimitUsageHashes[limitUsageCount] = getUsageHash(wallet, recoveredPayloadSigner, _payload.calls[i].to);
        expectedUsageAmounts[limitUsageCount] = totalUsage[i];
        limitUsageCount++;
      }
    }

    if (limitUsageCount != 0) {
      // Fix the array length
      assembly {
        mstore(expectedLimitUsageHashes, limitUsageCount)
        mstore(expectedUsageAmounts, limitUsageCount)
      }

      Payload.Call memory lastCall = _payload.calls[_payload.calls.length - 1];
      if (lastCall.behaviorOnError != Payload.BEHAVIOR_REVERT_ON_ERROR) {
        revert InvalidLimitUsageIncrement();
      }

      bytes32 expectedDataHash = keccak256(
        abi.encodeWithSelector(this.incrementLimitUsage.selector, expectedLimitUsageHashes, expectedUsageAmounts)
      );
      bytes32 actualDataHash = keccak256(lastCall.data);

      if (lastCall.to != address(this)) {
        revert MissingLimitUsageIncrement();
      }
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

  /// @notice Determines if a permission type has a usage limit
  /// @param pType The permission type to check
  /// @return bool True if the permission type has a limit, false otherwise
  function _hasLimit(
    Permissions.PermissionType pType
  ) internal pure returns (bool) {
    return pType == Permissions.PermissionType.ERC20 || pType == Permissions.PermissionType.ERC1155
      || pType == Permissions.PermissionType.NATIVE;
  }

  /// @notice Returns true if the contract implements the given interface
  /// @param interfaceId The interface identifier
  function supportsInterface(
    bytes4 interfaceId
  ) public pure returns (bool) {
    return interfaceId == type(ISapient).interfaceId || interfaceId == type(ISessionManager).interfaceId;
  }

}
