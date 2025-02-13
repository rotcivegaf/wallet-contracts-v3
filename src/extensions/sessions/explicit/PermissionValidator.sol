// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/interfaces/ISapient.sol";
import { LibBytes } from "../../../utils/LibBytes.sol";
import { ParameterOperation, ParameterRule, Permission, UsageLimit } from "./Permission.sol";

using LibBytes for bytes;

abstract contract PermissionValidator {

  mapping(bytes32 => uint256) public limitUsage;

  /// @notice Validates a rules permission
  /// @param permission The rules permission to validate
  /// @param call The call to validate against
  /// @param limitHashPrefix Prefix of the hash to use for tracking usage <wallet, signer>
  /// @param usageLimits Array of current usage limits
  /// @return True if the permission is valid, false otherwise
  /// @return newUsageLimits New array of usage limits
  function validatePermission(
    Permission memory permission,
    Payload.Call calldata call,
    bytes32 limitHashPrefix,
    UsageLimit[] memory usageLimits
  ) public view returns (bool, UsageLimit[] memory newUsageLimits) {
    if (permission.target != call.to) {
      return (false, usageLimits);
    }

    // Copy usage limits into array with space for new rules
    newUsageLimits = new UsageLimit[](usageLimits.length + permission.rules.length);
    for (uint256 i = 0; i < usageLimits.length; i++) {
      newUsageLimits[i] = usageLimits[i];
    }
    uint256 actualLimitsCount = usageLimits.length;

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
        // Find the usage limit for the current rule
        bytes32 usageHash = keccak256(abi.encode(limitHashPrefix, permission, i));
        uint256 previousUsage;
        for (actualLimitsCount = 0; actualLimitsCount < usageLimits.length; actualLimitsCount++) {
          if (usageLimits[actualLimitsCount].usageHash == bytes32(0)) {
            // Initialize new usage limit
            newUsageLimits[actualLimitsCount] = UsageLimit({ usageHash: usageHash, usageAmount: 0 });
            break;
          }
          if (usageLimits[actualLimitsCount].usageHash == usageHash) {
            previousUsage = usageLimits[actualLimitsCount].usageAmount;
            break;
          }
        }
        if (previousUsage == 0) {
          // Not in current payload, use storage
          previousUsage = limitUsage[usageHash];
        }
        // Cumulate usage
        value256 += previousUsage;
        if (previousUsage != 0) {
          newUsageLimits[actualLimitsCount].usageAmount = value256;
        }
        // Use the cumulative value for comparison
        value = bytes32(value256);
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
      mstore(newUsageLimits, actualLimitsCount)
    }

    return (true, newUsageLimits);
  }

  /// @notice Appends a new usage limit to the array
  /// @param usageLimits Array of current usage limits
  /// @param newUsageLimit New usage limit to append
  /// @return newUsageLimits New array of usage limits
  function _appendUsageLimits(
    UsageLimit[] memory usageLimits,
    UsageLimit memory newUsageLimit
  ) internal pure returns (UsageLimit[] memory) {
    UsageLimit[] memory newUsageLimits = new UsageLimit[](usageLimits.length + 1);
    for (uint256 i = 0; i < usageLimits.length; i++) {
      newUsageLimits[i] = usageLimits[i];
    }
    newUsageLimits[usageLimits.length] = newUsageLimit;
    return newUsageLimits;
  }

}
