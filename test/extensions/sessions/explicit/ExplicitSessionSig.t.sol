// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ParameterOperation, ParameterRule, Permission, UsageLimit } from "src/extensions/sessions/Permission.sol";
import {
  ExplicitSessionSig,
  ExplicitSessionSignature,
  Payload,
  SessionPermissions
} from "src/extensions/sessions/explicit/ExplicitSessionSig.sol";

import { PrimitivesRPC } from "../../../utils/PrimitivesRPC.sol";
import { AdvTest } from "../../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract ExplicitSessionSigImp is ExplicitSessionSig {

  function recoverSignature(
    Payload.Decoded memory payload,
    bytes calldata signature
  ) external pure returns (ExplicitSessionSignature memory) {
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

  function leftForPermissions(
    SessionPermissions memory permissions
  ) external pure returns (bytes32) {
    return _leafForPermissions(permissions);
  }

}

contract ExplicitSessionSigTest is AdvTest {

  ExplicitSessionSigImp public sessionSig;

  function setUp() public {
    sessionSig = new ExplicitSessionSigImp();
  }

  function test_explicit_decodePermissions(
    uint256 seed
  ) external {
    Permission memory permission;
    (permission, seed) = _randomPermission(seed);
    // Encode with ffi
    bytes memory encodedPermissions = PrimitivesRPC.toPackedPermission(vm, _permissionToJSON(permission));
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

  function test_explicit_recoverPermissionsTree_singleNode(
    uint256 seed
  ) external {
    // Generate a random permission
    SessionPermissions memory sessionPermission;
    (sessionPermission, seed) = _randomSessionPermission(seed);
    // Encode with ffi
    bytes memory encodedPermissions =
      PrimitivesRPC.toPackedSessionPermission(vm, _sessionPermissionToJSON(sessionPermission));
    // Encode into tree of a single node
    encodedPermissions = abi.encodePacked(uint8(0), encodedPermissions);
    bytes32 expectedRoot = sessionSig.leftForPermissions(sessionPermission); // Single node, root is leaf

    // Decode on contract
    (bytes32 root, SessionPermissions memory decodedPermissions) =
      sessionSig.recoverPermissionsTree(encodedPermissions, sessionPermission.signer);
    // Validate
    assertEq(root, expectedRoot, "Root");
    assertEq(decodedPermissions.signer, sessionPermission.signer, "Signer");
    assertEq(decodedPermissions.valueLimit, sessionPermission.valueLimit, "Value limit");
    assertEq(decodedPermissions.deadline, sessionPermission.deadline, "Deadline");
    assertEq(decodedPermissions.permissions.length, sessionPermission.permissions.length, "Permissions length");
    for (uint256 i = 0; i < decodedPermissions.permissions.length; i++) {
      assertEq(decodedPermissions.permissions[i].target, sessionPermission.permissions[i].target, "Permissions target");
      assertEq(
        decodedPermissions.permissions[i].rules.length,
        sessionPermission.permissions[i].rules.length,
        "Permissions rules length"
      );
      for (uint256 j = 0; j < decodedPermissions.permissions[i].rules.length; j++) {
        assertEq(
          decodedPermissions.permissions[i].rules[j].cumulative,
          sessionPermission.permissions[i].rules[j].cumulative,
          "Permissions rules cumulative"
        );
        assertEq(
          uint8(decodedPermissions.permissions[i].rules[j].operation),
          uint8(sessionPermission.permissions[i].rules[j].operation),
          "Permissions rules operation"
        );
        assertEq(
          decodedPermissions.permissions[i].rules[j].value,
          sessionPermission.permissions[i].rules[j].value,
          "Permissions rules value"
        );
        assertEq(
          decodedPermissions.permissions[i].rules[j].offset,
          sessionPermission.permissions[i].rules[j].offset,
          "Permissions rules offset"
        );
        assertEq(
          decodedPermissions.permissions[i].rules[j].mask,
          sessionPermission.permissions[i].rules[j].mask,
          "Permissions rules mask"
        );
      }
    }
  }

  function test_explicit_recoverPermissionsTree_random(
    uint256 seed
  ) external {
    uint256 maxDepth = _bound(seed, 1, 3);
    // Generate a random session topology using ffi
    string memory encodedTopology = PrimitivesRPC.randomSessionTopology(vm, maxDepth, 1, 1, seed);
    // Encode with ffi
    bytes memory encodedSessions = PrimitivesRPC.toPackedSessionTopology(vm, encodedTopology);
    // Decode on contract
    sessionSig.recoverPermissionsTree(encodedSessions, address(0));
  }

  function test_explicit_recoverPermissionsTree_cliEmptyAddRemove(uint256 seed, uint256 addCount) external {
    addCount = _bound(addCount, 1, 3);
    // Generate an empty session topology using ffi and populate it with a random session permission
    string memory topology = PrimitivesRPC.emptyExplicitSession(vm);
    SessionPermissions memory sessionPermission;
    {
      for (uint256 i = 0; i < addCount; i++) {
        (sessionPermission, seed) = _randomSessionPermission(seed);
        // Add the session permission to the topology
        topology = PrimitivesRPC.addExplicitSession(vm, _sessionPermissionToJSON(sessionPermission), topology);
        // Encode with ffi
        bytes memory encodedSessions = PrimitivesRPC.toPackedSessionTopology(vm, topology);
        // Decode on contract
        (, SessionPermissions memory decodedPermissions) =
          sessionSig.recoverPermissionsTree(encodedSessions, sessionPermission.signer);
        // Validate
        assertEq(decodedPermissions.signer, sessionPermission.signer, "Signer");
        assertEq(decodedPermissions.valueLimit, sessionPermission.valueLimit, "Value limit");
        assertEq(decodedPermissions.deadline, sessionPermission.deadline, "Deadline");
        assertEq(decodedPermissions.permissions.length, sessionPermission.permissions.length, "Permissions length");
      }
    }

    {
      // Remove the session permission from the topology
      topology =
        PrimitivesRPC.removeExplicitSession(vm, sessionPermission.signer, _sessionPermissionToJSON(sessionPermission));
      // Encode with ffi
      bytes memory encodedSessions = PrimitivesRPC.toPackedSessionTopology(vm, topology);
      // Decode on contract
      (, SessionPermissions memory decodedPermissions) =
        sessionSig.recoverPermissionsTree(encodedSessions, sessionPermission.signer);
      // Validate
      assertEq(decodedPermissions.signer, address(0), "Signer 0");
      assertEq(decodedPermissions.valueLimit, 0, "Value limit 0");
      assertEq(decodedPermissions.deadline, 0, "Deadline 0");
      assertEq(decodedPermissions.permissions.length, 0, "Permissions length 0");
    }
  }

  struct test_explicit_recoverSignature_cli_params {
    uint256 seed;
    uint256 signerPk;
    uint256 addCountBefore;
    uint256 addCountAfter;
    uint256 callCount;
  }

  function test_explicit_recoverSignature_cli(
    test_explicit_recoverSignature_cli_params memory params
  ) external {
    params.addCountBefore = _bound(params.addCountBefore, 0, 3);
    params.addCountAfter = _bound(params.addCountAfter, 0, 3);
    params.callCount = _bound(params.callCount, 1, 3);
    params.signerPk = boundPk(params.signerPk);
    // Add some random session permissions before the expected signer
    string memory topology = PrimitivesRPC.emptyExplicitSession(vm);
    {
      for (uint256 i = 0; i < params.addCountBefore; i++) {
        SessionPermissions memory sessionPermission;
        (sessionPermission, params.seed) = _randomSessionPermission(params.seed);
        // Add the session permission to the topology
        topology = PrimitivesRPC.addExplicitSession(vm, _sessionPermissionToJSON(sessionPermission), topology);
      }
    }
    address signerAddr = vm.addr(params.signerPk);
    {
      // Add the signer for this session
      SessionPermissions memory sessionPermission;
      (sessionPermission, params.seed) = _randomSessionPermission(params.seed);
      sessionPermission.signer = signerAddr;
      topology = PrimitivesRPC.addExplicitSession(vm, _sessionPermissionToJSON(sessionPermission), topology);
    }
    // Add some random session permissions after the expected signer
    {
      for (uint256 i = 0; i < params.addCountAfter; i++) {
        SessionPermissions memory sessionPermission;
        (sessionPermission, params.seed) = _randomSessionPermission(params.seed);
        // Add the session permission to the topology
        topology = PrimitivesRPC.addExplicitSession(vm, _sessionPermissionToJSON(sessionPermission), topology);
      }
    }

    // Generate a random payload
    Payload.Decoded memory payload;
    //FIXME Implement (payload, seed) = _randomPayload(seed);
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.signerPk, payloadHash);
    string memory sessionSignature = string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)));
    // Generate a random permission index per call
    uint8[] memory permissionIdxPerCall = new uint8[](params.callCount);
    {
      for (uint256 i = 0; i < params.callCount; i++) {
        bytes32 value;
        (value, params.seed) = useSeed(params.seed);
        permissionIdxPerCall[i] = uint8(uint256(value));
      }
    }

    // Encode with ffi
    bytes memory encodedSessions =
      PrimitivesRPC.useSessionExplicit(vm, sessionSignature, permissionIdxPerCall, topology);
    // Decode on contract
    ExplicitSessionSignature memory decodedSignature = sessionSig.recoverSignature(payload, encodedSessions);
    // Validate
    assertEq(decodedSignature.sessionPermissions.signer, signerAddr, "Signer");
    for (uint256 i = 0; i < decodedSignature.permissionIdxPerCall.length; i++) {
      assertEq(decodedSignature.permissionIdxPerCall[i], permissionIdxPerCall[i], "Permission index per call");
    }
  }
  // Helpers

  function _randomSessionPermission(
    uint256 seed
  ) internal pure returns (SessionPermissions memory sessionPermission, uint256 newSeed) {
    bytes32 result;
    // Generate a random signer
    (result, seed) = useSeed(seed);
    sessionPermission.signer = address(uint160(uint256(result)));
    console.log("sessionPermission.signer", sessionPermission.signer);
    // Generate a random value limit
    (result, seed) = useSeed(seed);
    sessionPermission.valueLimit = uint256(result);
    console.log("sessionPermission.valueLimit", sessionPermission.valueLimit);
    // Generate a random deadline
    (result, seed) = useSeed(seed);
    sessionPermission.deadline = uint256(result);
    console.log("sessionPermission.deadline", sessionPermission.deadline);
    // Generate random permissions
    (result, seed) = useSeed(seed);
    // uint256 permissionCount = uint256(result) % 3 + 1; // Max 3 permissions
    uint256 permissionCount = 1;
    sessionPermission.permissions = new Permission[](permissionCount);
    for (uint256 i = 0; i < permissionCount; i++) {
      (sessionPermission.permissions[i], seed) = _randomPermission(seed);
    }
    return (sessionPermission, seed);
  }

  function _randomPermission(
    uint256 seed
  ) internal pure returns (Permission memory permission, uint256 newSeed) {
    bytes32 value;
    (value, newSeed) = useSeed(seed);
    permission.target = address(uint160(uint256(value)));
    permission.rules = new ParameterRule[](1);
    (value, newSeed) = useSeed(newSeed);
    permission.rules[0].cumulative = uint256(value) % 2 == 0;
    (value, newSeed) = useSeed(newSeed);
    permission.rules[0].operation = ParameterOperation(uint256(value) % 4);
    (value, newSeed) = useSeed(newSeed);
    permission.rules[0].value = value;
    (value, newSeed) = useSeed(newSeed);
    permission.rules[0].offset = uint256(value);
    (value, newSeed) = useSeed(newSeed);
    permission.rules[0].mask = value;
    return (permission, newSeed);
  }

  function _sessionPermissionToJSON(
    SessionPermissions memory sessionPermission
  ) internal pure returns (string memory) {
    bytes memory json = "";
    for (uint256 i = 0; i < sessionPermission.permissions.length; i++) {
      if (i > 0) {
        json = abi.encodePacked(json, ",");
      }
      json = abi.encodePacked(json, _permissionToJSON(sessionPermission.permissions[i]));
    }
    return string(
      abi.encodePacked(
        '{"signer":"',
        vm.toString(sessionPermission.signer),
        '","valueLimit":"',
        vm.toString(sessionPermission.valueLimit),
        '","deadline":"',
        vm.toString(sessionPermission.deadline),
        '","permissions":[',
        json,
        "]}"
      )
    );
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
