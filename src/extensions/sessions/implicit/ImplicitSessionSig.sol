// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../../../utils/LibBytesPointer.sol";
import { LibOptim } from "../../../utils/LibOptim.sol";

import { Attestation, LibAttestation } from "../Attestation.sol";

import { Payload } from "../../../modules/Payload.sol";
import { LibPermission, Permission } from "../Permission.sol";
import { ImplicitSessionSignature } from "./IImplicitSessionManager.sol";
import { IImplicitSessionManagerSignals } from "./IImplicitSessionManager.sol";

contract ImplicitSessionSig is IImplicitSessionManagerSignals {

  using LibBytesPointer for bytes;
  using LibOptim for bytes;
  using LibAttestation for Attestation;

  function _recoverSignature(
    Payload.Decoded memory payload,
    bytes calldata encodedSignature
  ) internal pure returns (ImplicitSessionSignature memory signature) {
    uint256 pointer = 0;
    bytes32 r;
    bytes32 s;
    uint8 v;

    // Read session signature (r,sv)
    (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

    // Recover the session signer from the session signature
    bytes32 payloadHash = keccak256(abi.encode(payload));
    address recoveredPayloadSigner = ecrecover(payloadHash, v, r, s);

    // Read attestation components
    (signature.attestation, pointer) = LibAttestation.fromPacked(encodedSignature, pointer);
    if (recoveredPayloadSigner != signature.attestation.approvedSigner) {
      // Payload must be signed by the approved signer
      revert InvalidPayloadSigner(signature.attestation.approvedSigner, recoveredPayloadSigner);
    }

    // Read global signature (r,sv)
    (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

    // Recover the global signer from the global signature
    bytes32 attestationHash = signature.attestation.toHash();
    signature.globalSigner = ecrecover(attestationHash, v, r, s);

    // Read blacklist length and addresses
    uint256 dataSize;
    (dataSize, pointer) = encodedSignature.readUint24(pointer);
    signature.implicitBlacklist = new address[](dataSize);
    for (uint256 i = 0; i < dataSize; i++) {
      (signature.implicitBlacklist[i], pointer) = encodedSignature.readAddress(pointer);
    }

    return signature;
  }

}
