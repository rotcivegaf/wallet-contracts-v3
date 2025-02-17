// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { ParameterOperation, ParameterRule, Permission } from "src/extensions/sessions/explicit/Permission.sol";

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Payload } from "src/modules/Payload.sol";

using LibAttestation for Attestation;

contract SessionSigHarness {

  function recover(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) external pure returns (SessionSig.DecodedSignature memory) {
    return SessionSig.recoverSignature(payload, signature);
  }

}

contract TestSessionSig is Test {

  SessionSigHarness internal harness;
  Vm.Wallet internal sessionWallet;
  Vm.Wallet internal globalWallet;

  function setUp() public {
    harness = new SessionSigHarness();
    sessionWallet = vm.createWallet("session");
    globalWallet = vm.createWallet("global");
  }

  // -------------------------------------------------------------------------
  // TESTS
  // -------------------------------------------------------------------------

  /// @notice Tests the case for an explicit call signature.
  function testSingleExplicitSignature() public {
    Payload.Decoded memory payload = _buildPayload(1);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      valueLimit: 1000,
      deadline: 2000,
      permissions: new Permission[](1)
    });
    {
      sessionPerms.permissions[0] = Permission({ target: address(0xBEEF), rules: new ParameterRule[](1) });
      sessionPerms.permissions[0].rules[0] = ParameterRule({
        cumulative: false,
        operation: ParameterOperation.EQUAL,
        value: bytes32(0),
        offset: 0,
        mask: bytes32(0)
      });
    }

    // Create the topology from the CLI.
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
      string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
      topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    }

    // Sign the payload.
    bytes memory callSignature;
    {
      uint8 permissionIdx = 0;
      string memory sessionSignature = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
      callSignature = PrimitivesRPC.sessionExplicitEncodeCallSignature(vm, sessionSignature, permissionIdx);
    }

    // Construct the encoded signature.
    bytes memory encoded;
    {
      string[] memory callSignatures = new string[](1);
      callSignatures[0] = vm.toString(callSignature);
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, false);
    }

    // Recover and validate.
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 1, "Call signatures length");
      SessionSig.CallSignature memory callSig = sig.callSignatures[0];
      assertFalse(callSig.isImplicit, "Call should be explicit");
      assertEq(callSig.sessionSigner, sessionWallet.addr, "Recovered session signer");
      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 1, "Session permissions length");
      assertEq(sig.sessionPermissions[0].signer, sessionWallet.addr, "Session permission signer");
    }
  }

  function testSingleImplicitSignature() public {
    Payload.Decoded memory payload = _buildPayload(1);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    // Create attestation.
    Attestation memory attestation;
    {
      attestation = Attestation({
        approvedSigner: sessionWallet.addr,
        identityType: bytes4(0),
        issuerHash: bytes32(0),
        audienceHash: bytes32(0),
        authData: bytes(""),
        applicationData: bytes("")
      });
    }

    // Sign the payload.
    string memory callSignature =
      _createImplicitCallSignature(payload.calls[0], sessionWallet, globalWallet, attestation);

    // Create the topology from the CLI.
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
    }

    // Create the encoded signature.
    bytes memory encoded;
    {
      string[] memory callSignatures = new string[](1);
      callSignatures[0] = callSignature;
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, true);
    }

    // Recover and validate.
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 1, "Call signatures length");
      SessionSig.CallSignature memory callSig = sig.callSignatures[0];
      assertTrue(callSig.isImplicit, "Call should be implicit");
      assertEq(callSig.attestation.approvedSigner, sessionWallet.addr, "Recovered attestation signer");
      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 0, "Session permissions should be empty");
    }
  }

  function testMultipleImplicitSignatures() public {
    Payload.Decoded memory payload = _buildPayload(2);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test1",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });

      payload.calls[1] = Payload.Call({
        to: address(0xCAFE),
        value: 456,
        data: "test2",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    Attestation memory attestation = Attestation({
      approvedSigner: sessionWallet.addr,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: bytes(""),
      applicationData: bytes("")
    });

    // Create attestations and signatures for both calls
    string[] memory callSignatures = new string[](2);
    {
      callSignatures[0] = _createImplicitCallSignature(payload.calls[0], sessionWallet, globalWallet, attestation);
      callSignatures[1] = _createImplicitCallSignature(payload.calls[1], sessionWallet, globalWallet, attestation);
    }

    // Create the topology
    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);

    // Create the encoded signature
    bytes memory encoded;
    {
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, true);
    }

    // Recover and validate
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 2, "Call signatures length");

      for (uint256 i = 0; i < sig.callSignatures.length; i++) {
        SessionSig.CallSignature memory callSig = sig.callSignatures[i];
        assertTrue(callSig.isImplicit, "Call should be implicit");
        assertEq(callSig.attestation.approvedSigner, sessionWallet.addr, "Recovered attestation signer");
      }

      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 0, "Session permissions should be empty");
    }
  }

  /// @notice Tests the case for multiple explicit call signatures with different signers.
  function testMultipleExplicitSignatures() public {
    // Create a second session wallet
    Vm.Wallet memory sessionWallet2 = vm.createWallet("session2");

    Payload.Decoded memory payload = _buildPayload(2);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test1",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });

      payload.calls[1] = Payload.Call({
        to: address(0xCAFE),
        value: 456,
        data: "test2",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    // Create session permissions for both calls with different signers
    SessionPermissions[] memory sessionPermsArray = new SessionPermissions[](2);
    {
      sessionPermsArray[0] = _createSessionPermissions(address(0xBEEF), 1000, 2000, sessionWallet.addr);
      sessionPermsArray[1] = _createSessionPermissions(address(0xCAFE), 1000, 2000, sessionWallet2.addr);
    }

    // Create the topology from the CLI
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
      for (uint256 i = 0; i < sessionPermsArray.length; i++) {
        string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPermsArray[i]);
        topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
      }
    }

    // Sign the payloads and create call signatures with different signers
    bytes[] memory callSignatures = new bytes[](2);
    {
      // First call signed by sessionWallet
      string memory sessionSignature1 = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
      callSignatures[0] = PrimitivesRPC.sessionExplicitEncodeCallSignature(vm, sessionSignature1, 0);

      // Second call signed by sessionWallet2
      string memory sessionSignature2 = _signAndEncodeRSV(Payload.hashCall(payload.calls[1]), sessionWallet2);
      callSignatures[1] = PrimitivesRPC.sessionExplicitEncodeCallSignature(vm, sessionSignature2, 1);
    }

    // Construct the encoded signature
    bytes memory encoded;
    {
      string[] memory callSignaturesStr = new string[](2);
      for (uint256 i = 0; i < callSignatures.length; i++) {
        callSignaturesStr[i] = vm.toString(callSignatures[i]);
      }
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignaturesStr, false);
    }

    // Recover and validate
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 2, "Call signatures length");

      // Verify first signature
      assertFalse(sig.callSignatures[0].isImplicit, "First call should be explicit");
      assertEq(sig.callSignatures[0].sessionSigner, sessionWallet.addr, "First session signer");

      // Verify second signature
      assertFalse(sig.callSignatures[1].isImplicit, "Second call should be explicit");
      assertEq(sig.callSignatures[1].sessionSigner, sessionWallet2.addr, "Second session signer");

      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 2, "Session permissions length");
      assertEq(sig.sessionPermissions[1].signer, sessionWallet.addr, "Session permission signer 0");
      assertEq(sig.sessionPermissions[0].signer, sessionWallet2.addr, "Session permission signer 1");
    }
  }

  // -------------------------------------------------------------------------
  // HELPER FUNCTIONS
  // -------------------------------------------------------------------------

  function _signAndEncodeRSV(bytes32 hash, Vm.Wallet memory wallet) internal pure returns (string memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, hash);
    return string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)));
  }

  /// @dev Encodes the explicit config.
  function _encodeExplicitConfig(
    address signer,
    uint256 valueLimit,
    uint256 deadline
  ) internal pure returns (bytes memory) {
    bytes memory node = abi.encodePacked(
      uint8(SessionSig.FLAG_PERMISSIONS),
      signer,
      valueLimit,
      deadline,
      uint24(0) // empty permissions array length
    );
    return abi.encodePacked(uint24(node.length), node);
  }

  /// @dev Helper to build a Payload.Decoded with a given number of calls.
  function _buildPayload(
    uint256 callCount
  ) internal pure returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.noChainId = true;
    payload.space = 0;
    payload.nonce = 0;
    payload.parentWallets = new address[](0);
    payload.calls = new Payload.Call[](callCount);
  }

  function _sessionPermissionsToJSON(
    SessionPermissions memory sessionPerms
  ) internal pure returns (string memory) {
    string memory json = '{"signer":"';
    json = string.concat(json, vm.toString(sessionPerms.signer));
    json = string.concat(json, '","valueLimit":');
    json = string.concat(json, vm.toString(sessionPerms.valueLimit));
    json = string.concat(json, ',"deadline":');
    json = string.concat(json, vm.toString(sessionPerms.deadline));
    json = string.concat(json, ',"permissions":[');
    for (uint256 i = 0; i < sessionPerms.permissions.length; i++) {
      json = string.concat(json, _permissionToJSON(sessionPerms.permissions[i]));
    }
    json = string.concat(json, "]}");
    return json;
  }

  function _permissionToJSON(
    Permission memory permission
  ) internal pure returns (string memory) {
    string memory json = '{"target":"';
    json = string.concat(json, vm.toString(permission.target));
    json = string.concat(json, '","rules":[');
    for (uint256 i = 0; i < permission.rules.length; i++) {
      json = string.concat(json, _ruleToJSON(permission.rules[i]));
    }
    json = string.concat(json, "]}");
    return json;
  }

  function _ruleToJSON(
    ParameterRule memory rule
  ) internal pure returns (string memory) {
    string memory json = '{"cumulative":';
    json = string.concat(json, vm.toString(rule.cumulative));
    json = string.concat(json, ',"operation":');
    json = string.concat(json, vm.toString(uint8(rule.operation)));
    json = string.concat(json, ',"value":"');
    json = string.concat(json, vm.toString(rule.value));
    json = string.concat(json, '","offset":');
    json = string.concat(json, vm.toString(rule.offset));
    json = string.concat(json, ',"mask":"');
    json = string.concat(json, vm.toString(rule.mask));
    json = string.concat(json, '"}');
    return json;
  }

  function _attestationToJSON(
    Attestation memory attestation
  ) internal pure returns (string memory) {
    string memory json = '{"approvedSigner":"';
    json = string.concat(json, vm.toString(attestation.approvedSigner));
    json = string.concat(json, '","identityType":"');
    json = string.concat(json, vm.toString(attestation.identityType));
    json = string.concat(json, '","issuerHash":"');
    json = string.concat(json, vm.toString(attestation.issuerHash));
    json = string.concat(json, '","audienceHash":"');
    json = string.concat(json, vm.toString(attestation.audienceHash));
    json = string.concat(json, '","authData":"');
    json = string.concat(json, vm.toString(attestation.authData));
    json = string.concat(json, '","applicationData":"');
    json = string.concat(json, vm.toString(attestation.applicationData));
    json = string.concat(json, '"}');
    return json;
  }

  function _createImplicitCallSignature(
    Payload.Call memory call,
    Vm.Wallet memory signer,
    Vm.Wallet memory globalSigner,
    Attestation memory attestation
  ) internal returns (string memory) {
    string memory globalSignature = _signAndEncodeRSV(LibAttestation.toHash(attestation), globalSigner);
    string memory sessionSignature = _signAndEncodeRSV(Payload.hashCall(call), signer);

    bytes memory callSignature = PrimitivesRPC.sessionImplicitEncodeCallSignature(
      vm, sessionSignature, globalSignature, _attestationToJSON(attestation)
    );
    return vm.toString(callSignature);
  }

  function _createSessionPermissions(
    address target,
    uint256 valueLimit,
    uint256 deadline,
    address signer
  ) internal pure returns (SessionPermissions memory) {
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: signer,
      valueLimit: valueLimit,
      deadline: deadline,
      permissions: new Permission[](1)
    });

    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](1) });
    sessionPerms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(0),
      offset: 0,
      mask: bytes32(0)
    });

    return sessionPerms;
  }

}
