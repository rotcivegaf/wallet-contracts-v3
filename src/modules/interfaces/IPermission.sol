// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../Attestation.sol";
import { PermissionValidator } from "../PermissionValidator.sol";
import { ISapient, Payload } from "./ISapient.sol";

struct Permission {
  address target;
  ParameterRule[] rules;
}

enum ParameterOperation {
  EQUAL,
  NOT_EQUAL,
  GREATER_THAN_OR_EQUAL,
  LESS_THAN_OR_EQUAL
}

struct ParameterRule {
  ParameterOperation operation; // Operation to apply to the parameter
  bytes32 value; // Value to compare against
  uint256 offset; // Offset in calldata to read the parameter
  bytes32 mask; // Mask to apply to the parameter
  bool cumulative; // If the value should accumulate over multiple calls
    // FIXME tx call value?
}

struct UsageLimit {
  bytes32 usageHash;
  uint256 usageAmount;
}
