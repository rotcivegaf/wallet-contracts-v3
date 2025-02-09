// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Turn } from "./Turn.sol";
import { Calls } from "./modules/Calls.sol";
import { FixedAuth } from "./modules/auth/FixedAuth.sol";
import { IAuth } from "./modules/interfaces/IAuth.sol";

contract Fixed is Calls, FixedAuth {

  constructor(
    address _factory
  ) FixedAuth(_factory, address(new Turn())) { }

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(IAuth, FixedAuth) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
