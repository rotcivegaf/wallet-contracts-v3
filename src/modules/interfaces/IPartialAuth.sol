// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

interface IPartialAuth {

  function recoverPartialSignature(
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  )
    external
    view
    returns (
      uint256 threshold,
      uint256 weight,
      bool isValidImage,
      bytes32 imageHash,
      uint256 checkpoint,
      bytes32 opHash
    );

}
