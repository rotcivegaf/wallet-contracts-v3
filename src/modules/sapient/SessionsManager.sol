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

contract SessionsManager is ISessionManager {

  // Track usage per wallet/session/target
  mapping(bytes32 => uint256) private limitUsage;

  /// @inheritdoc ISessionManager
  function persistLimitUsage(address wallet, address sessionSigner, Payload.Decoded calldata payload) external {
    // First validate the limits again to ensure safety
    for (uint256 i = 0; i < payload.calls.length; i++) {
      bytes32 usageHash = _getUsageHash(wallet, sessionSigner, payload.calls[i].to);
      uint256 currentUsage = limitUsage[usageHash];
      uint256 usageAmount = _getUsageAmountFromCall(payload.calls[i]);
      if (usageAmount > 0 && currentUsage + usageAmount > type(uint256).max - currentUsage) {
        revert PermissionLimitExceeded(wallet, payload.calls[i].to);
      }
      limitUsage[usageHash] += usageAmount;
    }
  }

  function _getUsageHash(address wallet, address sessionAddress, address targetAddress) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(wallet, sessionAddress, targetAddress));
  }

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
    if (recoveredGlobalSigner != signature.sessionConfiguration.globalSigner) {
      revert InvalidAttestationSignature();
    }

    _validateSession(wallet, signature, _payload, recoveredPayloadSigner);

    // Generate and return imageHash
    return keccak256(abi.encode(signature.sessionConfiguration));
  }

  function _validateSession(
    address wallet,
    SessionSignature memory signature,
    Payload.Decoded calldata _payload,
    address recoveredPayloadSigner
  ) internal view {
    // Continue with existing validation
    if (signature.isImplicit) {
      _validateImplicitMode(wallet, signature, _payload, recoveredPayloadSigner);
    } else {
      _validateExplicitMode(wallet, signature, _payload, recoveredPayloadSigner);
    }
  }

  function _validateExplicitMode(
    address wallet,
    SessionSignature memory signature,
    Payload.Decoded calldata _payload,
    address recoveredPayloadSigner
  ) internal pure {
    SessionConfigurationPermissions[] memory sessionPermissions = signature.sessionConfiguration.sessionPermissions;

    // Binary search to find matching permissions for the signer
    uint256 left = 0;
    uint256 right = sessionPermissions.length - 1;
    Permissions.EncodedPermission[] memory permissions;
    while (left <= right) {
      uint256 mid = left + (right - left) / 2;
      address currentSigner = sessionPermissions[mid].signer;
      if (currentSigner == recoveredPayloadSigner) {
        permissions = sessionPermissions[mid].permissions;
        break;
      } else if (currentSigner < recoveredPayloadSigner) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }

    // Validate permissions for all calls in the payload
    for (uint256 i = 0; i < _payload.calls.length; i++) {
      bool isPermissionValid = false;
      for (uint256 j = 0; j < permissions.length; j++) {
        Permissions.EncodedPermission memory permission = permissions[j];

        if (Permissions.validatePermission(permission, _payload.calls[i])) {
          // Check if this permission has a limit
          if (_hasLimit(permission.pType)) {
            uint256 usageAmount = _getUsageAmount(permission, _payload.calls[i]);
            uint256 limit = _getLimit(permission);

            // Just verify the amount is within the total limit
            if (usageAmount > limit) {
              revert PermissionLimitExceeded(wallet, _payload.calls[i].to);
            }
          }

          isPermissionValid = true;
          break;
        }
      }
      if (!isPermissionValid) {
        revert MissingPermission(wallet, _payload.calls[i].to, bytes4(_payload.calls[i].data));
      }
    }
  }

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
      if (_isAddressBlacklisted(_payload.calls[i].to, blacklist)) {
        revert BlacklistedAddress(wallet, _payload.calls[i].to);
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

  // New helper function for binary search in blacklist
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

  function _hasLimit(
    Permissions.PermissionType pType
  ) internal pure returns (bool) {
    return pType == Permissions.PermissionType.ERC20_TRANSFER || pType == Permissions.PermissionType.ERC1155_TRANSFER
      || pType == Permissions.PermissionType.NATIVE_TRANSFER;
  }

  function _getLimit(
    Permissions.EncodedPermission memory permission
  ) internal pure returns (uint256) {
    if (permission.pType == Permissions.PermissionType.ERC20_TRANSFER) {
      Permissions.ERC20Permission memory ep = abi.decode(permission.data, (Permissions.ERC20Permission));
      return ep.limit;
    } else if (permission.pType == Permissions.PermissionType.ERC1155_TRANSFER) {
      Permissions.ERC1155Permission memory ep = abi.decode(permission.data, (Permissions.ERC1155Permission));
      return ep.limit;
    } else if (permission.pType == Permissions.PermissionType.NATIVE_TRANSFER) {
      Permissions.NativeTransferPermission memory np =
        abi.decode(permission.data, (Permissions.NativeTransferPermission));
      return np.limit;
    }
    return 0;
  }

  function _getUsageAmount(
    Permissions.EncodedPermission memory permission,
    Payload.Call calldata call
  ) internal pure returns (uint256) {
    if (permission.pType == Permissions.PermissionType.ERC20_TRANSFER) {
      (, uint256 amount) = abi.decode(call.data[4:], (address, uint256));
      return amount;
    } else if (permission.pType == Permissions.PermissionType.ERC1155_TRANSFER) {
      (,, uint256 amount) = abi.decode(call.data[4:], (address, uint256, uint256));
      return amount;
    } else if (permission.pType == Permissions.PermissionType.NATIVE_TRANSFER) {
      return call.value;
    }
    return 0;
  }

  // New helper function to get usage amount directly from call data
  function _getUsageAmountFromCall(
    Payload.Call calldata call
  ) internal pure returns (uint256) {
    bytes4 selector = bytes4(call.data);

    // ERC20 transfer/transferFrom
    if (selector == 0xa9059cbb || selector == 0x23b872dd) {
      (, uint256 amount) = abi.decode(call.data[4:], (address, uint256));
      return amount;
    }
    // ERC1155 safeTransferFrom
    else if (selector == 0xf242432a) {
      (,, uint256 amount,) = abi.decode(call.data[4:], (address, address, uint256, uint256));
      return amount;
    }
    // Native transfer (no selector needed)
    else if (call.value > 0) {
      return call.value;
    }

    return 0;
  }

  /// @notice Returns true if the contract implements the given interface
  /// @param interfaceId The interface identifier
  function supportsInterface(
    bytes4 interfaceId
  ) public pure returns (bool) {
    return interfaceId == type(ISapient).interfaceId || interfaceId == type(ISessionManager).interfaceId;
  }

}
