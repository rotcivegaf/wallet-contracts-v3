// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../utils/LibBytesPointer.sol";
import { LibOptim } from "../utils/LibOptim.sol";
import { ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX } from "./interfaces/ISignalsImplicitMode.sol";

using LibBytesPointer for bytes;
using LibOptim for bytes;

struct Attestation {
  address approvedSigner;
  bytes4 identityType;
  bytes32 issuerHash;
  bytes32 audienceHash;
  bytes authData;
  bytes applicationData;
}

library LibAttestation {

  function toHash(
    Attestation memory attestation
  ) internal pure returns (bytes32) {
    return keccak256(abi.encode(attestation));
  }

  function generateImplicitRequestMagic(Attestation memory attestation, address wallet) internal pure returns (bytes32) {
    return keccak256(
      abi.encodePacked(ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX, wallet, attestation.audienceHash, attestation.issuerHash)
    );
  }

}
