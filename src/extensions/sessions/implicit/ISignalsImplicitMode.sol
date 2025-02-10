// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/Payload.sol";
import { Attestation } from "../Attestation.sol";

bytes32 constant ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX = keccak256(abi.encodePacked("acceptImplicitRequest"));

interface ISignalsImplicitMode {

  function acceptImplicitRequest(
    address _wallet,
    // Attestation data
    Attestation calldata _attestation,
    bytes32 _redirectUrlHash, // Decoded from _attestation._authData as common usage expected
    // Transaction data
    Payload.Call calldata _call
  ) external view returns (bytes32);

}
