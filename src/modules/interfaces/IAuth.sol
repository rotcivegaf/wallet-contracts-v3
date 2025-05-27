// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

/// @title IAuth
/// @author Agustin Aguilar, Michael Standen, William Hua
/// @notice Internal interface for the auth modules
abstract contract IAuth {

  function _isValidImage(
    bytes32
  ) internal view virtual returns (bool isValid) {
    return false;
  }

  function _updateImageHash(
    bytes32 imageHash
  ) internal virtual;

}
