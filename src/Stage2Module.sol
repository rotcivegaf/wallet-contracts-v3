// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Calls } from "./modules/Calls.sol";
import { Stage2Auth } from "./modules/auth/Stage2Auth.sol";
import { IAuth } from "./modules/interfaces/IAuth.sol";

contract Stage2Module is Calls, Stage2Auth {

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(IAuth, Stage2Auth) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
