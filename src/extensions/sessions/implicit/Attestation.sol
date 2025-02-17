// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../../../utils/LibBytesPointer.sol";
import { ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX } from "./ISignalsImplicitMode.sol";

using LibBytesPointer for bytes;

struct Attestation {
  address approvedSigner;
  bytes4 identityType;
  bytes32 issuerHash;
  bytes32 audienceHash;
  bytes authData;
  bytes applicationData;
}

library LibAttestation {

  /// @notice Hashes an attestation
  function toHash(
    Attestation memory attestation
  ) internal pure returns (bytes32) {
    return keccak256(toPacked(attestation));
  }

  /// @notice Decodes an attestation from a packed bytes array
  /// @param encoded The packed bytes array
  /// @param pointer The pointer to the start of the attestation
  /// @return attestation The decoded attestation
  /// @return newPointer The new pointer to the end of the attestation
  function fromPacked(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Attestation memory attestation, uint256 newPointer) {
    newPointer = pointer;
    (attestation.approvedSigner, newPointer) = encoded.readAddress(newPointer);
    (attestation.identityType, newPointer) = encoded.readBytes4(newPointer);
    (attestation.issuerHash, newPointer) = encoded.readBytes32(newPointer);
    (attestation.audienceHash, newPointer) = encoded.readBytes32(newPointer);
    uint256 dataSize;
    (dataSize, newPointer) = encoded.readUint24(newPointer);
    attestation.authData = encoded[newPointer:newPointer + dataSize];
    newPointer += dataSize;
    (dataSize, newPointer) = encoded.readUint24(newPointer);
    attestation.applicationData = encoded[newPointer:newPointer + dataSize];
    newPointer += dataSize;
    return (attestation, newPointer);
  }

  /// @notice Encodes an attestation into a packed bytes array
  /// @param attestation The attestation to encode
  /// @return encoded The packed bytes array
  function toPacked(
    Attestation memory attestation
  ) internal pure returns (bytes memory encoded) {
    return abi.encodePacked(
      attestation.approvedSigner,
      attestation.identityType,
      attestation.issuerHash,
      attestation.audienceHash,
      uint24(attestation.authData.length),
      attestation.authData,
      uint24(attestation.applicationData.length),
      attestation.applicationData
    );
  }

  function generateImplicitRequestMagic(Attestation memory attestation, address wallet) internal pure returns (bytes32) {
    return keccak256(
      abi.encodePacked(ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX, wallet, attestation.audienceHash, attestation.issuerHash)
    );
  }

}
