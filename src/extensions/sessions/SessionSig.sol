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

  struct RecoverSignatureParams {
    uint256 pointer;
    address globalSigner;
    uint256 flags;
    uint256 dataSize;
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
    RecoverSignatureParams memory params;
    params.pointer = 0;

    // ----- Flags -----
    {
      (params.flags, params.pointer) = encodedSignature.readUint8(params.pointer);
      bool inferGlobalSigner = (params.flags & 1) != 0;

      if (inferGlobalSigner) {
        (params.globalSigner, params.pointer) = encodedSignature.readAddress(params.pointer);
      }
    }

    // ----- Explicit Config -----
    {
      // First read the length of the explicit config bytes (uint24)
      (params.dataSize, params.pointer) = encodedSignature.readUint24(params.pointer);
      // Recover the explicit session permissions tree
      // Note imageHash is not complete at this point
      (sig.imageHash, sig.sessionPermissions) =
        _recoverSessionPermissions(encodedSignature[params.pointer:params.pointer + params.dataSize]);
      params.pointer += params.dataSize;
    }

    // ----- Implicit Config -----
    {
      // Blacklist addresses length and array
      (params.dataSize, params.pointer) = encodedSignature.readUint24(params.pointer);
      sig.implicitBlacklist = new address[](params.dataSize);
      for (uint256 i = 0; i < params.dataSize; i++) {
        (sig.implicitBlacklist[i], params.pointer) = encodedSignature.readAddress(params.pointer);
      }
      // Add blacklist to imageHash
      // Note imageHash is not complete at this point
      sig.imageHash = LibOptim.fkeccak256(sig.imageHash, _leafForBlacklist(sig.implicitBlacklist));
    }

    // ----- Call Signatures -----
    {
      sig.callSignatures = new CallSignature[](payload.calls.length);
      {
        for (uint256 i = 0; i < payload.calls.length; i++) {
          CallSignature memory callSignature;
          // Determine signature type
          (callSignature.isImplicit, params.pointer) = encodedSignature.readBool(params.pointer);
          if (callSignature.isImplicit) {
            // Read attestation
            (callSignature.attestation, params.pointer) = LibAttestation.fromPacked(encodedSignature, params.pointer);
            // Read attestation global signature
            {
              bytes32 attestationHash = callSignature.attestation.toHash();
              // Recover the global signer from the attestation global signature
              address recoveredGlobalSigner;
              (recoveredGlobalSigner, params.pointer) =
                _readRSVAndRecover(encodedSignature, params.pointer, attestationHash);
              if (params.globalSigner == address(0)) {
                // Infer global signer from the first implicit call
                params.globalSigner = recoveredGlobalSigner;
              } else if (recoveredGlobalSigner != params.globalSigner) {
                // Global signer must be the same for all calls
                revert InvalidGlobalSigner();
              }
            }
          } else {
            // Read session permission used for the call
            (callSignature.sessionPermission, params.pointer) = encodedSignature.readUint8(params.pointer);
          }
          // Read session signature and recover the signer
          {
            bytes32 callHash = Payload.hashCall(payload.calls[i]);
            (callSignature.sessionSigner, params.pointer) =
              _readRSVAndRecover(encodedSignature, params.pointer, callHash);
          }

          sig.callSignatures[i] = callSignature;
        }
      }
    }

    // ----- Global signer -----
    if (params.globalSigner == address(0)) {
      // Could not derive the global signer from the signature
      revert InvalidGlobalSigner();
    }
    // Add global signer to imageHash
    sig.imageHash = LibOptim.fkeccak256(sig.imageHash, _leafForGlobalSigner(params.globalSigner));

    return sig;
  }

  struct RecoverSessionPermissionsParams {
    uint256 pointer;
    uint256 permissionsCount;
    uint256 flag;
    uint256 dataSize;
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
    RecoverSessionPermissionsParams memory params;
    params.pointer = 0;

    // Read permissions count
    {
      (params.permissionsCount, params.pointer) = encoded.readUint24(params.pointer);
      permissions = new SessionPermissions[](params.permissionsCount);
      params.permissionsCount = 0;
    }

    while (params.pointer < encoded.length) {
      // First byte is the flag (top 4 bits) and additional data (bottom 4 bits)
      uint256 firstByte;
      (firstByte, params.pointer) = encoded.readUint8(params.pointer);

      // The top 4 bits are the flag
      params.flag = (firstByte & 0xf0) >> 4;

      // Permissions configuration (0x00)
      if (params.flag == FLAG_PERMISSIONS) {
        SessionPermissions memory nodePermissions;

        // Read signer
        (nodePermissions.signer, params.pointer) = encoded.readAddress(params.pointer);

        // Read value limit
        (nodePermissions.valueLimit, params.pointer) = encoded.readUint256(params.pointer);

        // Read deadline
        (nodePermissions.deadline, params.pointer) = encoded.readUint256(params.pointer);

        // Read permissions array
        (nodePermissions.permissions, params.pointer) = _decodePermissions(encoded, params.pointer);

        // Update root
        {
          bytes32 node = _leafForPermissions(nodePermissions);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        }

        // Push node permissions to the permissions array
        permissions[params.permissionsCount++] = nodePermissions;
        continue;
      }

      // Node (0x01)
      if (params.flag == FLAG_NODE) {
        // Read pre-hashed node
        bytes32 node;
        (node, params.pointer) = encoded.readBytes32(params.pointer);

        // Update root
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      // Branch (0x02)
      if (params.flag == FLAG_BRANCH) {
        {
          // Read branch size
          uint256 size;
          {
            uint256 sizeSize = uint8(firstByte & 0x0f);
            (size, params.pointer) = encoded.readUintX(params.pointer, sizeSize);
          }

          // Process branch
          uint256 nrindex = params.pointer + size;
          (bytes32 branchRoot, SessionPermissions[] memory branchPermissions) =
            _recoverSessionPermissions(encoded[params.pointer:nrindex]);
          params.pointer = nrindex;

          // Push all branch permissions to the permissions array
          for (uint256 i = 0; i < branchPermissions.length; i++) {
            permissions[params.permissionsCount++] = branchPermissions[i];
          }

          // Update root
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, branchRoot) : branchRoot;
        }
        continue;
      }

      revert InvalidNodeType(params.flag);
    }

    // Truncate permissions array to the actual number of permissions
    //FIXME Or should this throw an error?
    if (params.permissionsCount < permissions.length) {
      {
        uint256 permissionsCount = params.permissionsCount;
        assembly {
          mstore(permissions, permissionsCount)
        }
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

  /// @notice Reads the R, S, V and recovers the signer from the encoded data.
  function _readRSVAndRecover(
    bytes calldata encoded,
    uint256 pointer,
    bytes32 digest
  ) internal pure returns (address recovered, uint256 newPointer) {
    uint8 v;
    bytes32 r;
    bytes32 s;
    (r, s, v, newPointer) = encoded.readRSVCompact(pointer);
    return (ecrecover(digest, v, r, s), newPointer);
  }

}
