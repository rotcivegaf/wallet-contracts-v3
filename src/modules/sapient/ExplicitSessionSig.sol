// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { LibOptim } from "../../utils/LibOptim.sol";

import { Payload } from "../Payload.sol";
import { LibPermission, Permission } from "../Permission.sol";
import { ExplicitSessionSignature, SessionPermissions } from "../interfaces/IExplicitSessionManager.sol";

contract ExplicitSessionSig {

  using LibBytesPointer for bytes;
  using LibOptim for bytes;
  using LibPermission for Permission;

  uint256 internal constant FLAG_PERMISSIONS = 0;
  uint256 internal constant FLAG_NODE = 1;
  uint256 internal constant FLAG_BRANCH = 2;

  error InvalidNodeType(uint256 flag);

  function _recoverSignature(
    Payload.Decoded memory payload,
    bytes calldata encodedSignature
  ) internal pure returns (ExplicitSessionSignature memory signature) {
    uint256 pointer = 0;
    bytes32 r;
    bytes32 s;
    uint8 v;

    // Read session signature (r,sv)
    (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

    // Recover the session signer from the session signature
    bytes32 payloadHash = keccak256(abi.encode(payload));
    address recoveredPayloadSigner = ecrecover(payloadHash, v, r, s);

    // Read global signature (r,sv)
    (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

    // Read encoded permissions size and data
    uint256 dataSize;
    (dataSize, pointer) = encodedSignature.readUint24(pointer);
    bytes calldata encodedPermissionsTree = encodedSignature[pointer:pointer + dataSize];
    pointer += dataSize;

    // Recover permissions tree and find signer's permissions
    (signature.permissionsRoot, signature.sessionPermissions) =
      _recoverPermissionsTree(encodedPermissionsTree, recoveredPayloadSigner);

    // Read permission indices length and values
    uint256 remainingBytes = encodedSignature.length - pointer;
    signature.permissionIdxPerCall = new uint8[](remainingBytes);
    for (uint256 i = 0; i < remainingBytes; i++) {
      (signature.permissionIdxPerCall[i], pointer) = encodedSignature.readUint8(pointer);
    }

    return signature;
  }

  function _recoverPermissionsTree(
    bytes calldata encodedSessions,
    address sessionSigner
  ) internal pure returns (bytes32 root, SessionPermissions memory permissions) {
    uint256 rindex;

    while (rindex < encodedSessions.length) {
      // First byte is the flag (top 4 bits) and additional data (bottom 4 bits)
      (uint256 firstByte, uint256 tmpIndex) = encodedSessions.readUint8(rindex);
      rindex = tmpIndex;

      // The top 4 bits are the flag
      uint256 flag = (firstByte & 0xf0) >> 4;

      // Permissions configuration (0x00)
      if (flag == FLAG_PERMISSIONS) {
        SessionPermissions memory nodePermissions;

        // Read signer
        (nodePermissions.signer, rindex) = encodedSessions.readAddress(rindex);

        // Read value limit
        (nodePermissions.valueLimit, rindex) = encodedSessions.readUint256(rindex);

        // Read deadline
        (nodePermissions.deadline, rindex) = encodedSessions.readUint256(rindex);

        // Read permissions array
        uint256 nrindex;
        (nodePermissions.permissions, nrindex) = _decodePermissions(encodedSessions[rindex:], 0);
        rindex += nrindex;

        // Compute node hash
        bytes32 node = _leafForPermissions(nodePermissions);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;

        if (nodePermissions.signer == sessionSigner) {
          permissions = nodePermissions;
        }
        continue;
      }

      // Node (0x01)
      if (flag == FLAG_NODE) {
        // Read pre-hashed node
        bytes32 node;
        (node, rindex) = encodedSessions.readBytes32(rindex);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      // Branch (0x02)
      if (flag == FLAG_BRANCH) {
        // Read branch size
        uint256 sizeSize = uint8(firstByte & 0x0f);
        uint256 size;
        (size, rindex) = encodedSessions.readUintX(rindex, sizeSize);

        // Process branch
        uint256 nrindex = rindex + size;
        (bytes32 branchRoot, SessionPermissions memory branchPermissions) =
          _recoverPermissionsTree(encodedSessions[rindex:nrindex], sessionSigner);
        if (branchPermissions.signer == sessionSigner) {
          permissions = branchPermissions;
        }

        root = root != bytes32(0) ? LibOptim.fkeccak256(root, branchRoot) : branchRoot;
        rindex = nrindex;
        continue;
      }

      revert InvalidNodeType(flag);
    }

    return (root, permissions);
  }

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

}
