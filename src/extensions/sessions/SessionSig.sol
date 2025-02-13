// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../modules/Payload.sol";
import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { LibOptim } from "../../utils/LibOptim.sol";
import { SessionPermissions } from "./explicit/IExplicitSessionManager.sol";
import { LibPermission, Permission } from "./explicit/Permission.sol";
import { Attestation, LibAttestation } from "./implicit/Attestation.sol";

using LibBytesPointer for bytes;
using LibAttestation for Attestation;

library SessionSig {

  uint256 internal constant FLAG_PERMISSIONS = 0;
  uint256 internal constant FLAG_NODE = 1;
  uint256 internal constant FLAG_BRANCH = 2;

  error InvalidNodeType(uint256 flag);
  error InvalidGlobalSigner();

  struct CallSignature {
    bool isImplicit;
    address sessionSigner;
    uint8 sessionPermission; // For explicit
    Attestation attestation; // For implicit
  }

  struct DecodedSignature {
    bytes32 imageHash;
    address[] implicitBlacklist;
    SessionPermissions[] sessionPermissions;
    CallSignature[] callSignatures;
  }

  /// @notice Recovers the decoded signature from the encodedSignature bytes.
  /// The encoded layout is:
  /// - flags: [uint8]
  ///   - bit 0: infer global signer from implicit_signature
  /// - globalSigner: [address] - skipped if bit 0 of flags is not set
  /// - explicit_config: [uint24 length, <SessionPermissions encoded>]
  /// - implicit_config: [uint24 blacklistLength, blacklist addresses...]
  /// - call_signatures: [<CallSignature encoded>] - Size is payload.calls.length
  ///   - call_signature: [bool is_implicit, <data encoded>]
  ///     - if is_implicit: implicit_signature: [<Attestation encoded>, <attestation_signature>, <session_signature>]
  ///     - if !is_implicit: explicit_signature: [uint8 session_permission, <session_signature>]
  function recoverSignature(
    Payload.Decoded calldata payload,
    bytes calldata encodedSignature
  ) internal pure returns (DecodedSignature memory sig) {
    uint256 pointer = 0;
    address globalSigner;

    // ----- Flags -----
    {
      uint256 flags;
      (flags, pointer) = encodedSignature.readUint8(pointer);
      bool inferGlobalSigner = flags & 1 != 0;

      if (inferGlobalSigner) {
        (globalSigner, pointer) = encodedSignature.readAddress(pointer);
      }
    }

    // ----- Explicit Config -----
    {
      // First read the length of the explicit config bytes (uint24)
      uint256 dataSize;
      (dataSize, pointer) = encodedSignature.readUint24(pointer);
      // Recover the explicit session permissions tree
      // Note imageHash is not complete at this point
      (sig.imageHash, sig.sessionPermissions) = _recoverSessionPermissions(encodedSignature[pointer:pointer + dataSize]);
      pointer += dataSize;
    }

    // ----- Implicit Config -----
    {
      // Blacklist addresses length and array
      uint256 dataSize;
      (dataSize, pointer) = encodedSignature.readUint24(pointer);
      sig.implicitBlacklist = new address[](dataSize);
      for (uint256 i = 0; i < dataSize; i++) {
        (sig.implicitBlacklist[i], pointer) = encodedSignature.readAddress(pointer);
      }
      // Add blacklist to imageHash
      // Note imageHash is not complete at this point
      sig.imageHash = LibOptim.fkeccak256(sig.imageHash, _leafForBlacklist(sig.implicitBlacklist));
    }

    // ----- Call Signatures -----
    {
      uint256 dataSize = payload.calls.length;
      sig.callSignatures = new CallSignature[](dataSize);
      {
        for (uint256 i = 0; i < dataSize; i++) {
          CallSignature memory callSignature;
          // Determine signature type
          (callSignature.isImplicit, pointer) = encodedSignature.readBool(pointer);
          if (callSignature.isImplicit) {
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
              if (globalSigner == address(0)) {
                // Infer global signer from the first implicit call
                globalSigner = recoveredGlobalSigner;
              } else if (recoveredGlobalSigner != globalSigner) {
                // Global signer must be the same for all calls
                revert InvalidGlobalSigner();
              }
            }
          } else {
            // Read session permission used for the call
            (callSignature.sessionPermission, pointer) = encodedSignature.readUint8(pointer);
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

    // ----- Global signer -----
    if (globalSigner == address(0)) {
      // Could not derive the global signer from the signature
      revert InvalidGlobalSigner();
    }
    // Add global signer to imageHash
    sig.imageHash = LibOptim.fkeccak256(sig.imageHash, _leafForGlobalSigner(globalSigner));

    return sig;
  }

  /// @notice Recovers the session permissions tree from the encoded data.
  /// The encoded layout is:
  /// - permissions_count: [uint24]
  /// - permissions_tree_element: [flag, <data>]
  ///   - flag: [uint8]
  ///   - data: [data]
  ///     - if flag == FLAG_PERMISSIONS: [SessionPermissions encoded]
  ///     - if flag == FLAG_NODE: [bytes32 node]
  ///     - if flag == FLAG_BRANCH: [uint256 size, nested encoding...]
  function _recoverSessionPermissions(
    bytes calldata encoded
  ) internal pure returns (bytes32 root, SessionPermissions[] memory permissions) {
    uint256 pointer = 0;

    // Read permissions count
    uint256 permissionsCount;
    {
      (permissionsCount, pointer) = encoded.readUint24(pointer);
      permissions = new SessionPermissions[](permissionsCount);
      permissionsCount = 0;
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
          bytes32 node = _leafForPermissions(nodePermissions);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        }

        // Push node permissions to the permissions array
        permissions[permissionsCount++] = nodePermissions;
        continue;
      }

      // Node (0x01)
      if (flag == FLAG_NODE) {
        // Read pre-hashed node
        bytes32 node;
        (node, pointer) = encoded.readBytes32(pointer);

        // Update root
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      // Branch (0x02)
      if (flag == FLAG_BRANCH) {
        {
          // Read branch size
          uint256 size;
          {
            uint256 sizeSize = uint8(firstByte & 0x0f);
            (size, pointer) = encoded.readUintX(pointer, sizeSize);
          }

          // Process branch
          uint256 nrindex = pointer + size;
          (bytes32 branchRoot, SessionPermissions[] memory branchPermissions) =
            _recoverSessionPermissions(encoded[pointer:nrindex]);
          pointer = nrindex;

          // Push all branch permissions to the permissions array
          for (uint256 i = 0; i < branchPermissions.length; i++) {
            permissions[permissionsCount++] = branchPermissions[i];
          }

          // Update root
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, branchRoot) : branchRoot;
        }
        continue;
      }

      revert InvalidNodeType(flag);
    }

    // Truncate permissions array to the actual number of permissions
    //FIXME Or should this throw an error?
    if (permissionsCount < permissions.length) {
      assembly {
        mstore(permissions, permissionsCount)
      }
    }

    return (root, permissions);
  }

  /// @notice Decodes an array of Permission objects from the encoded data.
  function _decodePermissions(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Permission[] memory permissions, uint256 newPointer) {
    uint256 length;
    (length, pointer) = encoded.readUint24(pointer);
    permissions = new Permission[](length);
    for (uint256 i = 0; i < length; i++) {
      (permissions[i], pointer) = LibPermission.readPermission(encoded, pointer);
    }
    return (permissions, pointer);
  }

  /// @notice Hashes the session permissions into a leaf node.
  function _leafForPermissions(
    SessionPermissions memory permissions
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        "Session permissions leaf:\n",
        permissions.signer,
        permissions.valueLimit,
        permissions.deadline,
        permissions.permissions
      )
    );
  }

  /// @notice Hashes the blacklist into a leaf node.
  function _leafForBlacklist(
    address[] memory blacklist
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(blacklist));
  }

  /// @notice Hashes the global signer into a leaf node.
  function _leafForGlobalSigner(
    address globalSigner
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(globalSigner));
  }

}
