// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";

import { SessionSig } from "src/extensions/sessions/SessionSig.sol";

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Payload } from "src/modules/Payload.sol";

contract SessionSigHarness {

  function recover(
    Payload.Decoded memory payload,
    bytes calldata signature
  ) external pure returns (SessionSig.DecodedSignature memory) {
    return SessionSig.recoverSignature(payload, signature);
  }

}

contract SessionSigTest is Test {

  using LibAttestation for Attestation;

  SessionSigHarness harness;

  function setUp() public {
    harness = new SessionSigHarness();
  }

  // -------------------------------------------------------------------------
  // HELPER FUNCTIONS
  // -------------------------------------------------------------------------

  /// @dev Encodes a uint24 (3 bytes) in big-endian.
  function encodeUint24(
    uint256 value
  ) internal pure returns (bytes memory) {
    return abi.encodePacked(bytes1(uint8(value >> 16)), bytes1(uint8(value >> 8)), bytes1(uint8(value)));
  }

  /**
   * @dev Encodes an "explicit config" for the session permissions.
   *
   * Here we simulate a single node with FLAG_PERMISSIONS (0) containing:
   * - signer, valueLimit, deadline and an empty permissions array.
   *
   * The encoding is:
   *   explicitNode = abi.encodePacked(uint8(0), signer, valueLimit, deadline, encodeUint24(0))
   * and then the explicit config is prefixed with its length (uint24).
   */
  function encodeExplicitConfig(
    address signer,
    uint256 valueLimit,
    uint256 deadline
  ) internal pure returns (bytes memory) {
    bytes memory node = abi.encodePacked(
      uint8(SessionSig.FLAG_PERMISSIONS), // flag 0
      signer,
      valueLimit,
      deadline,
      encodeUint24(0) // empty permissions array length
    );
    return abi.encodePacked(encodeUint24(node.length), node);
  }

  /// @dev Encodes the implicit config. Here we use an empty blacklist.
  function encodeImplicitConfig() internal pure returns (bytes memory) {
    return encodeUint24(0);
  }

  /// @dev Encodes an RSV compact signature (r, s, v).
  function encodeRSV(uint8 v, bytes32 r, bytes32 s) internal pure returns (bytes memory) {
    return abi.encodePacked(r, s, v);
  }

  // -------------------------------------------------------------------------
  // TESTS
  // -------------------------------------------------------------------------

  /// @notice Tests the case for an explicit call signature.
  function testExplicitSignature() public {
    // Build a payload with one call.
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.noChainId = true;
    payload.space = 0;
    payload.nonce = 0;
    payload.parentWallets = new address[](0);
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: address(0xBEEF),
      value: 123,
      data: "test",
      gasLimit: 21000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    bytes32 callHash = Payload.hashCall(payload.calls[0]);

    // Sign the call hash with a known private key.
    uint256 sessionPk = 1;
    address expectedSigner = vm.addr(sessionPk);
    (uint8 vSession, bytes32 rSession, bytes32 sSession) = vm.sign(sessionPk, callHash);

    // Build the encoded signature.
    // 1. Flags: For explicit calls, inferGlobalSigner flag is false (0).
    bytes memory encoded = abi.encodePacked(uint8(0));

    // 2. Explicit config: a single node with our session permission.
    bytes memory explicitConfig = encodeExplicitConfig(expectedSigner, 1000, 2000);
    encoded = abi.encodePacked(encoded, explicitConfig);

    // 3. Implicit config: empty blacklist.
    bytes memory implicitConfig = encodeImplicitConfig();
    encoded = abi.encodePacked(encoded, implicitConfig);

    // 4. Call signatures: one call.
    // For an explicit call, encode: bool false, then a dummy session permission index (0),
    // then the session signature (RSV compact).
    encoded = abi.encodePacked(encoded, false, uint8(0), encodeRSV(vSession, rSession, sSession));

    // Recover and validate.
    SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
    assertEq(sig.callSignatures.length, 1, "Call signatures length");
    SessionSig.CallSignature memory callSig = sig.callSignatures[0];
    assertFalse(callSig.isImplicit, "Call should be explicit");
    assertEq(callSig.sessionSigner, expectedSigner, "Recovered session signer");
    assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
    assertEq(sig.sessionPermissions.length, 1, "Session permissions length");
    assertEq(sig.sessionPermissions[0].signer, expectedSigner, "Session permission signer");
  }

  /// @notice Tests the case for an implicit call signature.
  function testImplicitSignature() public {
    // Build a payload with one call.
    Payload.Decoded memory payload;
    {
      payload.kind = Payload.KIND_TRANSACTIONS;
      payload.noChainId = true;
      payload.space = 0;
      payload.nonce = 0;
      payload.parentWallets = new address[](0);
      payload.calls = new Payload.Call[](1);
      payload.calls[0] = Payload.Call({
        to: address(0xCAFE),
        value: 456,
        data: "implicit",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    bytes32 callHash = Payload.hashCall(payload.calls[0]);
    bytes memory encoded;
    address expectedSessionSigner;
    bytes32 dummyAttestationData;

    {
      // For implicit calls, include a global signer
      Vm.Wallet memory globalWallet = vm.createWallet("global");

      // Create dummy attestation
      dummyAttestationData = keccak256("attestation");
      bytes memory attestationEncoded = abi.encodePacked(dummyAttestationData);

      // Sign attestation hash using global signer
      (uint8 vAtt, bytes32 rAtt, bytes32 sAtt) = vm.sign(globalWallet.privateKey, dummyAttestationData);

      // Session signature setup
      Vm.Wallet memory sessionWallet = vm.createWallet("session");
      expectedSessionSigner = sessionWallet.addr;
      (uint8 vSession, bytes32 rSession, bytes32 sSession) = vm.sign(sessionWallet.privateKey, callHash);

      // Build encoded signature in stages
      encoded = abi.encodePacked(uint8(1)); // Flags
      encoded = abi.encodePacked(encoded, globalWallet.addr); // Global signer

      // Explicit config
      bytes memory explicitConfig = encodeExplicitConfig(expectedSessionSigner, 0, 0);
      encoded = abi.encodePacked(encoded, explicitConfig);

      // Implicit config
      bytes memory implicitConfig = encodeImplicitConfig();
      encoded = abi.encodePacked(encoded, implicitConfig);

      // Call signatures
      encoded = abi.encodePacked(
        encoded, true, attestationEncoded, encodeRSV(vAtt, rAtt, sAtt), encodeRSV(vSession, rSession, sSession)
      );
    }

    // Recover and validate
    SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
    assertEq(sig.callSignatures.length, 1, "Call signatures length");
    SessionSig.CallSignature memory callSig = sig.callSignatures[0];
    assertTrue(callSig.isImplicit, "Call should be implicit");
    assertEq(callSig.sessionSigner, expectedSessionSigner, "Recovered session signer");
    bytes32 recoveredAttestationData = callSig.attestation.toHash();
    assertEq(recoveredAttestationData, dummyAttestationData, "Attestation data");
    assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
    assertEq(sig.sessionPermissions.length, 1, "Session permissions length");
  }

  /// @notice Tests a mixed case with one explicit call and one implicit call.
  function testMixedSignatures() public {
    // Build a payload with two calls.
    Payload.Decoded memory payload;
    {
      payload.kind = Payload.KIND_TRANSACTIONS;
      payload.noChainId = true;
      payload.space = 0;
      payload.nonce = 0;
      payload.parentWallets = new address[](0);
      payload.calls = new Payload.Call[](2);

      // Call 0: explicit.
      payload.calls[0] = Payload.Call({
        to: address(0xDEAD),
        value: 111,
        data: "explicit",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
      // Call 1: implicit.
      payload.calls[1] = Payload.Call({
        to: address(0xBEEF),
        value: 222,
        data: "implicit",
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    bytes memory encoded;
    address expectedExplicitSigner;
    address expectedImplicitSigner;

    {
      // --- Explicit call (index 0) ---
      bytes32 callHashExplicit = Payload.hashCall(payload.calls[0]);
      Vm.Wallet memory explicitWallet = vm.createWallet("explicit");
      expectedExplicitSigner = explicitWallet.addr;

      // --- Implicit call (index 1) ---
      bytes32 callHashImplicit = Payload.hashCall(payload.calls[1]);
      Vm.Wallet memory globalWallet = vm.createWallet("global");
      Vm.Wallet memory implicitSessionWallet = vm.createWallet("implicitSession");
      expectedImplicitSigner = implicitSessionWallet.addr;

      // Build the encoded signature.
      // 1. Flags: Since we include an implicit call, set inferGlobalSigner bit (1).
      encoded = abi.encodePacked(uint8(1));
      // 2. Global signer.
      encoded = abi.encodePacked(encoded, globalWallet.addr);
      // 3. Explicit config: encode a node for the explicit permission.
      bytes memory explicitConfig = encodeExplicitConfig(explicitWallet.addr, 500, 1000);
      encoded = abi.encodePacked(encoded, explicitConfig);
      // 4. Implicit config: empty blacklist.
      bytes memory implicitConfig = encodeImplicitConfig();
      encoded = abi.encodePacked(encoded, implicitConfig);

      // 5. Call signatures: first explicit, then implicit
      // Explicit signature
      {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(explicitWallet.privateKey, callHashExplicit);
        encoded = abi.encodePacked(
          encoded,
          false, // isImplicit = false
          uint8(0), // dummy session permission index
          encodeRSV(v, r, s)
        );
      }

      // Implicit signatures (attestation + call)
      {
        bytes32 dummyAttestationData = keccak256("mixedAttestation");
        bytes memory attestationEncoded = abi.encodePacked(dummyAttestationData);
        encoded = abi.encodePacked(
          encoded,
          true, // isImplicit = true
          attestationEncoded
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(globalWallet.privateKey, dummyAttestationData);
        encoded = abi.encodePacked(encoded, encodeRSV(v, r, s));
        (v, r, s) = vm.sign(implicitSessionWallet.privateKey, callHashImplicit);
        encoded = abi.encodePacked(encoded, encodeRSV(v, r, s));
      }
    }

    // Recover and validate.
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 2, "Call signatures length");
      // First call: explicit.
      assertFalse(sig.callSignatures[0].isImplicit, "First call explicit");
      assertEq(sig.callSignatures[0].sessionSigner, expectedExplicitSigner, "Explicit signer");
      // Second call: implicit.
      assertTrue(sig.callSignatures[1].isImplicit, "Second call implicit");
      assertEq(sig.callSignatures[1].sessionSigner, expectedImplicitSigner, "Implicit signer");
      assertEq(sig.implicitBlacklist.length, 0, "Blacklist empty");
      assertEq(sig.sessionPermissions.length, 1, "Session permissions length");
    }
  }

}
