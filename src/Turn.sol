// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Calls } from "./modules/Calls.sol";
import { TurnAuth } from "./modules/auth/TurnAuth.sol";
import { IAuth } from "./modules/interfaces/IAuth.sol";

contract Turn is Calls, TurnAuth {

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(IAuth, TurnAuth) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
