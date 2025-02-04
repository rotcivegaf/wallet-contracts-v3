// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../utils/LibBytesPointer.sol";
import { Attestation } from "./Attestation.sol";
import { ISapient, Payload } from "./interfaces/ISapient.sol";
import { PermissionValidator } from "./sapient/PermissionValidator.sol";

import { console } from "forge-std/console.sol";

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
  bool cumulative; // If the value should accumulate over multiple calls
  ParameterOperation operation; // Operation to apply to the parameter
  bytes32 value; // Value to compare against
  uint256 offset; // Offset in calldata to read the parameter
  bytes32 mask; // Mask to apply to the parameter
}

struct UsageLimit {
  bytes32 usageHash;
  uint256 usageAmount;
}

library LibPermission {

  using LibBytesPointer for bytes;

  function toHash(
    Permission memory permission
  ) internal pure returns (bytes32) {
    return keccak256(abi.encode(permission));
  }

  function readPermission(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Permission memory permission, uint256 newPointer) {
    // Target
    (permission.target, pointer) = encoded.readAddress(pointer);
    console.log("permission.target", permission.target);
    // Rules
    uint256 rulesLength;
    (rulesLength, pointer) = encoded.readUint24(pointer);
    console.log("rulesLength", rulesLength);
    permission.rules = new ParameterRule[](rulesLength);
    for (uint256 i = 0; i < rulesLength; i++) {
      uint8 operationCumulative;
      (operationCumulative, pointer) = encoded.readUint8(pointer);
      console.log("operationCumulative", operationCumulative);
      // 000X: cumulative
      permission.rules[i].cumulative = operationCumulative & 1 != 0;
      // XXX0: operation
      permission.rules[i].operation = ParameterOperation(operationCumulative >> 1);

      (permission.rules[i].value, pointer) = encoded.readBytes32(pointer);
      console.log("permission.rules[i].value");
      console.logBytes32(permission.rules[i].value);
      (permission.rules[i].offset, pointer) = encoded.readUint256(pointer);
      console.log("permission.rules[i].offset", permission.rules[i].offset);
      (permission.rules[i].mask, pointer) = encoded.readBytes32(pointer);
      console.log("permission.rules[i].mask");
      console.logBytes32(permission.rules[i].mask);
    }
    return (permission, pointer);
  }

  function toPacked(
    Permission calldata permission
  ) internal pure returns (bytes memory packed) {
    bytes memory encoded = abi.encodePacked(permission.target, uint24(permission.rules.length));
    for (uint256 i = 0; i < permission.rules.length; i++) {
      encoded = abi.encodePacked(encoded, ruleToPacked(permission.rules[i]));
    }
    return encoded;
  }

  function ruleToPacked(
    ParameterRule calldata rule
  ) internal pure returns (bytes memory packed) {
    // Combine operation and cumulative flag into a single byte
    // 0x[operationx3][cumulative]
    uint8 operationCumulative = (uint8(rule.operation) << 1) | (rule.cumulative ? 1 : 0);

    return abi.encodePacked(operationCumulative, rule.value, rule.offset, rule.mask);
  }

}
