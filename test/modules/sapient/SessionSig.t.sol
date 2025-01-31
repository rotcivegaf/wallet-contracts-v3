// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ParameterOperation, ParameterRule, Permission, UsageLimit } from "../../../src/modules/Permission.sol";
import {
  Payload, SessionManagerSignature, SessionPermissions, SessionSig
} from "../../../src/modules/sapient/SessionSig.sol";

import { PrimitivesCli } from "../../utils/PrimitivesCli.sol";

import { AdvTest } from "../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract SessionSigImp is SessionSig {

  function recoverSignature(
    Payload.Decoded memory payload,
    bytes calldata signature
  ) external pure returns (SessionManagerSignature memory) {
    return _recoverSignature(payload, signature);
  }

  function recoverPermissionsTree(
    bytes calldata encodedSessions,
    address sessionSigner
  ) external pure returns (bytes32 root, SessionPermissions memory) {
    return _recoverPermissionsTree(encodedSessions, sessionSigner);
  }

  function decodePermissions(
    bytes calldata encodedPermissions
  ) external pure returns (Permission[] memory permissions) {
    (permissions,) = _decodePermissions(encodedPermissions, 0);
    return permissions;
  }

}

contract SessionSigTest is AdvTest {

  SessionSigImp public sessionSig;

  function setUp() public {
    sessionSig = new SessionSigImp();
  }

  function test_decodePermissions(
    uint256 seed
  ) external {
    Permission memory permission;
    (permission, seed) = _randomPermission(seed);
    // Encode with ffi
    bytes memory encodedPermissions = PrimitivesCli.toPackedPermission(vm, _permissionToJSON(permission));
    // Prepend length of 1
    encodedPermissions = abi.encodePacked(uint24(1), encodedPermissions);
    // Decode on contract
    Permission[] memory decodedPermissions = sessionSig.decodePermissions(encodedPermissions);
    // Validate
    assertEq(decodedPermissions.length, 1, "Decoded length");
    assertEq(decodedPermissions[0].target, permission.target, "Decoded target");
    assertEq(decodedPermissions[0].rules.length, permission.rules.length, "Decoded rules length");
    for (uint256 i = 0; i < decodedPermissions[0].rules.length; i++) {
      assertEq(decodedPermissions[0].rules[i].cumulative, permission.rules[i].cumulative, "Decoded cumulative");
      assertEq(
        uint8(decodedPermissions[0].rules[i].operation), uint8(permission.rules[i].operation), "Decoded operation"
      );
      assertEq(decodedPermissions[0].rules[i].value, permission.rules[i].value, "Decoded value");
      assertEq(decodedPermissions[0].rules[i].offset, permission.rules[i].offset, "Decoded offset");
      assertEq(decodedPermissions[0].rules[i].mask, permission.rules[i].mask, "Decoded mask");
    }
  }

  function _randomPermission(
    uint256 seed
  ) internal pure returns (Permission memory permission, uint256 newSeed) {
    bytes32 value;
    (value, newSeed) = _useSeed(seed);
    permission.target = address(uint160(uint256(value)));
    permission.rules = new ParameterRule[](1);
    (value, newSeed) = _useSeed(newSeed);
    permission.rules[0].cumulative = uint256(value) % 2 == 0;
    (value, newSeed) = _useSeed(newSeed);
    permission.rules[0].operation = ParameterOperation(uint256(value) % 4);
    (value, newSeed) = _useSeed(newSeed);
    permission.rules[0].value = value;
    (value, newSeed) = _useSeed(newSeed);
    permission.rules[0].offset = uint256(value);
    (value, newSeed) = _useSeed(newSeed);
    permission.rules[0].mask = value;
    return (permission, newSeed);
  }

  function _useSeed(
    uint256 seed
  ) internal pure returns (bytes32 value, uint256 newSeed) {
    value = keccak256(abi.encode(seed));
    newSeed = uint256(value);
  }

  function _permissionToJSON(
    Permission memory permission
  ) internal pure returns (string memory) {
    bytes memory json = abi.encodePacked('{"target":"', vm.toString(permission.target), '","rules":[');
    for (uint256 i = 0; i < permission.rules.length; i++) {
      json = abi.encodePacked(
        json,
        '{"cumulative":',
        vm.toString(permission.rules[i].cumulative),
        ',"operation":',
        vm.toString(uint8(permission.rules[i].operation)),
        ',"value":"',
        vm.toString(permission.rules[i].value),
        '","offset":"',
        vm.toString(permission.rules[i].offset),
        '","mask":"',
        vm.toString(permission.rules[i].mask),
        '"}'
      );
    }
    json = abi.encodePacked(json, "]}");
    return string(json);
  }

}
