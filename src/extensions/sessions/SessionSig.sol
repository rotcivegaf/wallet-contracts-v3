// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../modules/Payload.sol";
import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { LibOptim } from "../../utils/LibOptim.sol";
import { SessionErrors } from "./SessionErrors.sol";
import { SessionPermissions } from "./explicit/IExplicitSessionManager.sol";
import { LibPermission, Permission } from "./explicit/Permission.sol";
import { Attestation, LibAttestation } from "./implicit/Attestation.sol";

using LibBytesPointer for bytes;
using LibAttestation for Attestation;

library SessionSig {

  uint256 internal constant FLAG_PERMISSIONS = 0;
  uint256 internal constant FLAG_NODE = 1;
  uint256 internal constant FLAG_BRANCH = 2;
  uint256 internal constant FLAG_BLACKLIST = 3;
  uint256 internal constant FLAG_GLOBAL_SIGNER = 4;

  struct CallSignature {
    bool isImplicit;
    address sessionSigner;
    uint8 sessionPermission; // For explicit
    Attestation attestation; // For implicit
  }

  struct DecodedSignature {
    bytes32 imageHash;
    address globalSigner;
    address[] implicitBlacklist;
    SessionPermissions[] sessionPermissions;
    CallSignature[] callSignatures;
  }

  /// @notice Recovers the decoded signature from the encodedSignature bytes.
  /// The encoded layout is:
  /// - session_configuration: [uint8 flags, <data>]
  ///   - flags: [uint8]
  ///     - 0: [uint8 permissions_count, <SessionPermissions encoded>]
  ///     - 1: [bytes32 node]
  ///     - 2: [uint256 size, nested encoding...]
  ///     - 3: [uint24 blacklist_length, blacklist_addresses...]
  ///     - 4: [address global_signer]
  /// - call_signatures: [<CallSignature encoded>] - Size is payload.calls.length
  ///   - call_signature: [uint8 call_flags, <data encoded>]
  ///       - call_flags: [bool is_implicit, <see_below>]
  ///     - if call_flags.is_implicit: implicit_signature: [<Attestation encoded>, <attestation_signature>, <session_signature>]
  ///     - if !call_flags.is_implicit: explicit_signature: [uint (call_flag 7 bits) session_permission, <session_signature>]
  function recoverSignature(
    Payload.Decoded calldata payload,
    bytes calldata encodedSignature
  ) internal pure returns (DecodedSignature memory sig) {
    uint256 pointer = 0;
    bool hasBlacklistInConfig;

    // ----- Session Configuration -----
    {
      // First read the length of the session configuration bytes (uint24)
      uint256 dataSize;
      (dataSize, pointer) = encodedSignature.readUint24(pointer);
      // Recover the session configuration
      (sig, hasBlacklistInConfig) = recoverConfiguration(encodedSignature[pointer:pointer + dataSize]);
      pointer += dataSize;

      // Global signer must be set
      if (sig.globalSigner == address(0)) {
        // Global signer was not set
        revert SessionErrors.InvalidGlobalSigner();
      }
    }

    // ----- Call Signatures -----
    {
      uint256 dataSize = payload.calls.length;
      sig.callSignatures = new CallSignature[](dataSize);
      {
        for (uint256 i = 0; i < dataSize; i++) {
          CallSignature memory callSignature;
          // Determine signature type
          uint8 flag;
          (flag, pointer) = encodedSignature.readUint8(pointer);
          callSignature.isImplicit = flag & 0x80 != 0;
          if (callSignature.isImplicit) {
            if (!hasBlacklistInConfig) {
              // Blacklist must be in configuration when using implicit signatures
              revert SessionErrors.InvalidBlacklist();
            }
            //TODO Find a way to wrap up multiple uses of the same attestation and global signature
            // Read attestation
            (callSignature.attestation, pointer) = LibAttestation.fromPacked(encodedSignature, pointer);
            // Read attestation global signature
            {
              bytes32 r;
              bytes32 s;
              uint8 v;
              (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);
              // Recover the global signer from the attestation global signature
              bytes32 attestationHash = callSignature.attestation.toHash();
              address recoveredGlobalSigner = ecrecover(attestationHash, v, r, s);
              if (recoveredGlobalSigner != sig.globalSigner) {
                // Global signer must match configuration
                revert SessionErrors.InvalidGlobalSigner();
              }
            }
          } else {
            // Session permission idx is the flag (first bit 0)
            callSignature.sessionPermission = flag;
          }
          // Read session signature and recover the signer
          {
            bytes32 r;
            bytes32 s;
            uint8 v;
            (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);
            bytes32 callHash = Payload.hashCall(payload.calls[i]);
            callSignature.sessionSigner = ecrecover(callHash, v, r, s);
          }

          sig.callSignatures[i] = callSignature;
        }
      }
    }

    return sig;
  }

  /// @notice Recovers the session configuration from the encoded data.
  /// The encoded layout is:
  /// - permissions_count: [uint8]
  /// - permissions_tree_element: [flag, <data>]
  ///   - flag: [uint8]
  ///   - data: [data]
  ///     - if flag == FLAG_PERMISSIONS: [SessionPermissions encoded]
  ///     - if flag == FLAG_NODE: [bytes32 node]
  ///     - if flag == FLAG_BRANCH: [uint256 size, nested encoding...]
  ///     - if flag == FLAG_BLACKLIST: [uint24 blacklist_count, blacklist_addresses...]
  ///     - if flag == FLAG_GLOBAL_SIGNER: [address global_signer]
  /// @dev A valid configuration must have exactly one global signer and at most one blacklist.
  function recoverConfiguration(
    bytes calldata encoded
  ) internal pure returns (DecodedSignature memory sig, bool hasBlacklist) {
    uint256 pointer;
    uint256 permissionsCount;

    // Guess maximum permissions size by bytes length
    {
      uint256 maxPermissionsSize = encoded.length / 50; // 50 is min bytes per permission
      sig.sessionPermissions = new SessionPermissions[](maxPermissionsSize);
    }

    while (pointer < encoded.length) {
      // First byte is the flag (top 4 bits) and additional data (bottom 4 bits)
      uint256 firstByte;
      (firstByte, pointer) = encoded.readUint8(pointer);
      // The top 4 bits are the flag
      uint256 flag = (firstByte & 0xf0) >> 4;

      // Permissions configuration (0x00)
      if (flag == FLAG_PERMISSIONS) {
        SessionPermissions memory nodePermissions;
        uint256 pointerStart = pointer;

        // Read signer
        (nodePermissions.signer, pointer) = encoded.readAddress(pointer);

        // Read value limit
        (nodePermissions.valueLimit, pointer) = encoded.readUint256(pointer);

        // Read deadline
        (nodePermissions.deadline, pointer) = encoded.readUint256(pointer);

        // Read permissions array
        (nodePermissions.permissions, pointer) = _decodePermissions(encoded, pointer);

        // Update root
        {
          bytes32 permissionHash = _leafHashForPermissions(encoded[pointerStart:pointer]);
          sig.imageHash =
            sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, permissionHash) : permissionHash;
        }

        // Push node permissions to the permissions array
        sig.sessionPermissions[permissionsCount++] = nodePermissions;
        continue;
      }

      // Node (0x01)
      if (flag == FLAG_NODE) {
        // Read pre-hashed node
        bytes32 node;
        (node, pointer) = encoded.readBytes32(pointer);

        // Update root
        sig.imageHash = sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, node) : node;

        continue;
      }

      // Branch (0x02)
      if (flag == FLAG_BRANCH) {
        // Read branch size
        uint256 size;
        {
          uint256 sizeSize = uint8(firstByte & 0x0f);
          (size, pointer) = encoded.readUintX(pointer, sizeSize);
        }
        // Process branch
        uint256 nrindex = pointer + size;
        (DecodedSignature memory branchSig, bool branchHasBlacklist) = recoverConfiguration(encoded[pointer:nrindex]);
        pointer = nrindex;

        // Store the branch blacklist
        if (branchHasBlacklist) {
          if (hasBlacklist) {
            // Blacklist already set
            revert SessionErrors.InvalidBlacklist();
          }
          hasBlacklist = true;
          sig.implicitBlacklist = branchSig.implicitBlacklist;
        }

        // Store the branch global signer
        if (branchSig.globalSigner != address(0)) {
          if (sig.globalSigner != address(0)) {
            // Global signer already set
            revert SessionErrors.InvalidGlobalSigner();
          }
          sig.globalSigner = branchSig.globalSigner;
        }

        // Push all branch permissions to the permissions array
        for (uint256 i = 0; i < branchSig.sessionPermissions.length; i++) {
          sig.sessionPermissions[permissionsCount++] = branchSig.sessionPermissions[i];
        }

        // Update root
        sig.imageHash =
          sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, branchSig.imageHash) : branchSig.imageHash;
        continue;
      }

      // Blacklist (0x03)
      if (flag == FLAG_BLACKLIST) {
        if (hasBlacklist) {
          // Blacklist already set
          revert SessionErrors.InvalidBlacklist();
        }
        hasBlacklist = true;

        // Read the blacklist count from the first byte
        uint256 blacklistCount = uint256(firstByte & 0x0f);
        if (blacklistCount == 0x0f) {
          // Read the blacklist count from the next byte
          (blacklistCount, pointer) = encoded.readUint8(pointer);
        }
        uint256 pointerStart = pointer;
        // Read the blacklist addresses
        sig.implicitBlacklist = new address[](blacklistCount);
        for (uint256 i = 0; i < blacklistCount; i++) {
          (sig.implicitBlacklist[i], pointer) = encoded.readAddress(pointer);
        }

        // Update the root
        bytes32 blacklistHash = _leafHashForBlacklist(encoded[pointerStart:pointer]);
        sig.imageHash = sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, blacklistHash) : blacklistHash;

        continue;
      }

      // Global signer (0x04)
      if (flag == FLAG_GLOBAL_SIGNER) {
        if (sig.globalSigner != address(0)) {
          // Global signer already set
          revert SessionErrors.InvalidGlobalSigner();
        }
        (sig.globalSigner, pointer) = encoded.readAddress(pointer);

        // Update the root
        bytes32 globalSignerHash = _leafHashForGlobalSigner(sig.globalSigner);
        sig.imageHash =
          sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, globalSignerHash) : globalSignerHash;

        continue;
      }

      revert SessionErrors.InvalidNodeType(flag);
    }

    {
      // Update the permissions array length
      SessionPermissions[] memory permissions = sig.sessionPermissions;
      assembly {
        mstore(permissions, permissionsCount)
      }
      sig.sessionPermissions = permissions;
    }

    return (sig, hasBlacklist);
  }

  /// @notice Decodes an array of Permission objects from the encoded data.
  function _decodePermissions(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Permission[] memory permissions, uint256 newPointer) {
    uint256 length;
    (length, pointer) = encoded.readUint8(pointer);
    permissions = new Permission[](length);
    for (uint256 i = 0; i < length; i++) {
      (permissions[i], pointer) = LibPermission.readPermission(encoded, pointer);
    }
    return (permissions, pointer);
  }

  /// @notice Hashes the encoded session permissions into a leaf node.
  function _leafHashForPermissions(
    bytes calldata encodedPermissions
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(uint8(FLAG_PERMISSIONS), encodedPermissions));
  }

  /// @notice Hashes the encoded blacklist into a leaf node.
  function _leafHashForBlacklist(
    bytes calldata encodedBlacklist
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(uint8(FLAG_BLACKLIST), encodedBlacklist));
  }

  /// @notice Hashes the global signer into a leaf node.
  function _leafHashForGlobalSigner(
    address globalSigner
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(uint8(FLAG_GLOBAL_SIGNER), globalSigner));
  }

}
