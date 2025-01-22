// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { IPermissionValidator } from "../../src/modules/interfaces/IPermissionValidator.sol";
import { Payload } from "../../src/modules/interfaces/ISapient.sol";

contract MockPermissionValidator is IPermissionValidator {

  bool public shouldAllow;

  constructor(
    bool _shouldAllow
  ) {
    shouldAllow = _shouldAllow;
  }

  function validatePermission(bytes calldata data, Payload.Call calldata call) external view returns (bool) {
    // Simple validation that checks if data matches call.data
    return shouldAllow && keccak256(data) == keccak256(call.data);
  }

}
