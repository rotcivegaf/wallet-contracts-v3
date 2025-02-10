// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../../../utils/LibBytes.sol";
import { LibBytesPointer } from "../../../utils/LibBytesPointer.sol";
import { Attestation, LibAttestation } from "../Attestation.sol";

import { ISapient, Payload } from "../../../modules/interfaces/ISapient.sol";
import { IImplicitSessionManager, ImplicitSessionSignature } from "./IImplicitSessionManager.sol";
import { ISignalsImplicitMode } from "./ISignalsImplicitMode.sol";
import { ImplicitSessionSig } from "./ImplicitSessionSig.sol";

using LibBytesPointer for bytes;
using LibBytes for bytes;
using LibAttestation for Attestation;

contract ImplicitSessionManager is ImplicitSessionSig, IImplicitSessionManager {

  /// @inheritdoc ISapient
  /// @dev The image hash derived from the global signer and session configuration
  function isValidSapientSignature(
    Payload.Decoded calldata payload,
    bytes calldata encodedSignature
  ) external view returns (bytes32) {
    // Recover the session manager signature
    ImplicitSessionSignature memory signature = _recoverSignature(payload, encodedSignature);

    // Validate the session using recovered permissions
    address wallet = msg.sender;
    _validateSession(wallet, payload, signature);

    // Generate and return the image hash
    return getImageHash(signature);
  }

  /// @notice Generates an image hash for the given session manager decoded signature
  /// @param signature The session manager signature
  /// @return bytes32 The generated image hash
  function getImageHash(
    ImplicitSessionSignature memory signature
  ) public pure returns (bytes32) {
    return keccak256(abi.encode(signature.globalSigner, signature.implicitBlacklist));
  }

  /// @notice Validates the implicit session
  /// @param wallet The wallet's address
  /// @param payload The decoded payload containing calls
  /// @param signature The session signature data
  function _validateSession(
    address wallet,
    Payload.Decoded calldata payload,
    ImplicitSessionSignature memory signature
  ) internal view {
    // Validate blacklist
    address[] memory blacklist = signature.implicitBlacklist;

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
    return interfaceId == type(ISapient).interfaceId || interfaceId == type(IImplicitSessionManager).interfaceId;
  }

}
