// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

abstract contract IAuth {

  function _isValidImage(
    bytes32
  ) internal view virtual returns (bool) {
    return false;
  }

  function _updateImageHash(
    bytes32 _imageHash
  ) internal virtual;

}
