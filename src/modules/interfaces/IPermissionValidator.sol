// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

interface IPermissionValidator {

  function validatePermission(bytes memory _data, Payload.Call calldata _call) external view returns (bool);

}
