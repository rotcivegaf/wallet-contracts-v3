// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation, LibAttestation } from "../../src/modules/Attestation.sol";
import { Payload } from "../../src/modules/interfaces/ISapient.sol";
import { ISignalsImplicitMode } from "../../src/modules/interfaces/ISignalsImplicitMode.sol";

using LibAttestation for Attestation;

contract MockImplicitContract is ISignalsImplicitMode {

  function acceptImplicitRequest(
    address wallet,
    Attestation calldata attestation,
    bytes32,
    Payload.Call calldata
  ) external pure returns (bytes32) {
    return attestation.generateImplicitRequestMagic(wallet);
  }

}
