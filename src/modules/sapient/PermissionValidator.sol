// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../../utils/LibBytes.sol";

import { ParameterOperation, ParameterRule, Permission, UsageLimit } from "../Permission.sol";
import { Payload } from "../interfaces/ISapient.sol";

abstract contract PermissionValidator {

  using LibBytes for bytes;

  mapping(bytes32 => uint256) public limitUsage;

  /// @notice Validates a rules permission
  /// @param permission The rules permission to validate
  /// @param call The call to validate against
  /// @param limitHashPrefix Prefix of the hash to use for tracking usage
  /// @return True if the permission is valid, false otherwise
  /// @return usageLimits Array of usage limits
  function validatePermission(
    Permission memory permission,
    Payload.Call calldata call,
    bytes32 limitHashPrefix
  ) public view returns (bool, UsageLimit[] memory usageLimits) {
    if (permission.target != call.to) {
      return (false, usageLimits);
    }

    usageLimits = new UsageLimit[](permission.rules.length);
    uint256 cumulativeIndex = 0;

    // Check each rule
    for (uint256 i = 0; i < permission.rules.length; i++) {
      ParameterRule memory rule = permission.rules[i];

      // Ensure call data is long enough
      if (call.data.length < rule.offset + 32) {
        return (false, usageLimits);
      }

      // Extract value from calldata at offset
      bytes32 value = call.data.readBytes32(rule.offset);

      // Apply mask
      value = value & rule.mask;

      if (rule.cumulative) {
        // Calculate cumulative usage
        uint256 value256 = uint256(value);
        bytes32 usageHash = keccak256(abi.encode(limitHashPrefix, permission));
        usageLimits[cumulativeIndex] = UsageLimit({ usageHash: usageHash, usageAmount: value256 });
        cumulativeIndex++;
        uint256 previousUsage = limitUsage[usageHash];
        // Use the cumulative value for comparison
        value = bytes32(value256 + previousUsage);
      }

      // Compare based on operation
      if (rule.operation == ParameterOperation.EQUAL) {
        if (value != rule.value) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.LESS_THAN_OR_EQUAL) {
        if (uint256(value) > uint256(rule.value)) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.NOT_EQUAL) {
        if (value == rule.value) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.GREATER_THAN_OR_EQUAL) {
        if (uint256(value) < uint256(rule.value)) {
          return (false, usageLimits);
        }
      }
    }

    // Fix array length
    assembly {
      mstore(usageLimits, cumulativeIndex)
    }

    return (true, usageLimits);
  }

}
