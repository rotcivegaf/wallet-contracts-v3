// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

import { Passkeys } from "../../../src/extensions/passkeys/Passkeys.sol";
import { WebAuthn } from "../../../src/utils/WebAuthn.sol";
import { PrimitivesRPC } from "../../utils/PrimitivesRPC.sol";
import { AdvTest } from "../../utils/TestUtils.sol";

// Harness contract to expose internal functions for testing
contract PasskeysImp is Passkeys {

  function rootForPasskeyPub(
    bool _requireUserVerification,
    bytes32 _x,
    bytes32 _y,
    bytes32 _metadata
  ) external pure returns (bytes32) {
    return _rootForPasskey(_requireUserVerification, _x, _y, _metadata);
  }

  function decodeSignaturePub(
    bytes calldata _signature
  )
    external
    pure
    returns (
      WebAuthn.WebAuthnAuth memory _webAuthnAuth,
      bool _requireUserVerification,
      bytes32 _x,
      bytes32 _y,
      bytes32 _metadata
    )
  {
    return _decodeSignature(_signature);
  }

}

contract PasskeysTest is AdvTest {

  PasskeysImp public passkeysImp;

  function setUp() public {
    passkeysImp = new PasskeysImp();
  }

  // --- _rootForPasskey Tests ---

  // Fuzz test for _rootForPasskey using metadataHash
  function test_rootForPasskey_metadataHash(
    bool requireUserVerification,
    bytes32 x,
    bytes32 y,
    bytes32 metadataHash
  ) public {
    bytes32 contractRoot = passkeysImp.rootForPasskeyPub(requireUserVerification, x, y, metadataHash);

    PrimitivesRPC.PasskeyPublicKey memory pkParams;
    pkParams.x = x;
    pkParams.y = y;
    pkParams.requireUserVerification = requireUserVerification;
    pkParams.metadataHash = metadataHash;

    bytes32 rpcRoot = PrimitivesRPC.passkeysComputeRoot(vm, pkParams);

    assertEq(contractRoot, rpcRoot, "Contract root hash should match RPC root hash using metadataHash");
  }

  // Fuzz test for _rootForPasskey using credentialId
  function test_rootForPasskey_credentialId(
    bool requireUserVerification,
    bytes32 x,
    bytes32 y,
    uint256 credentialIdSeed
  ) public {
    string memory credentialId = generateRandomString(credentialIdSeed);
    vm.assume(bytes(credentialId).length > 0);
    bytes32 expectedMetadataNodeHash = keccak256(bytes(credentialId));
    bytes32 contractRoot = passkeysImp.rootForPasskeyPub(requireUserVerification, x, y, expectedMetadataNodeHash);

    PrimitivesRPC.PasskeyPublicKey memory pkParams;
    pkParams.x = x;
    pkParams.y = y;
    pkParams.requireUserVerification = requireUserVerification;
    pkParams.credentialId = credentialId;

    bytes32 rpcRoot = PrimitivesRPC.passkeysComputeRoot(vm, pkParams);

    assertEq(contractRoot, rpcRoot, "Contract root hash should match RPC root hash using credentialId");
  }

  // Fuzz test for _rootForPasskey without metadata
  function test_rootForPasskey_noMetadata(bool requireUserVerification, bytes32 x, bytes32 y) public {
    bytes32 noMetadataHash = bytes32(0);
    bytes32 contractRoot = passkeysImp.rootForPasskeyPub(requireUserVerification, x, y, noMetadataHash);

    PrimitivesRPC.PasskeyPublicKey memory pkParams;
    pkParams.x = x;
    pkParams.y = y;
    pkParams.requireUserVerification = requireUserVerification;

    bytes32 rpcRoot = PrimitivesRPC.passkeysComputeRoot(vm, pkParams);

    assertEq(contractRoot, rpcRoot, "Contract root hash should match RPC root hash without metadata");
  }

  struct test_decodeSignature_packed_params {
    bool requireUserVerification;
    bytes32 x;
    bytes32 y;
    bytes32 r;
    bytes32 s;
    bytes authenticatorData;
    bytes challengeBytes;
    bytes32 metadataHash;
    bool embedMetadata;
    uint256 typeValueSeed;
    uint256 originValueSeed;
  }

  struct test_decodeSignature_packed_vars {
    string clientDataJSON;
    uint256 challengeIndex;
    uint256 typeIndex;
    PrimitivesRPC.PasskeyPublicKey pkParams;
    PrimitivesRPC.PasskeySignatureComponents sigParams;
    bytes encodedSignature;
    WebAuthn.WebAuthnAuth decodedAuth;
    bool decodedRUV;
    bytes32 decodedX;
    bytes32 decodedY;
    bytes32 decodedMetadata;
    string typeValue;
    string originValue;
  }

  function test_decodeSignature_packed(
    test_decodeSignature_packed_params memory params
  ) public {
    vm.assume(params.authenticatorData.length > 0 && params.authenticatorData.length <= 65535);
    vm.assume(params.challengeBytes.length > 0 && params.challengeBytes.length < 100);
    vm.assume(params.r != bytes32(0));
    vm.assume(params.s != bytes32(0));

    if (params.embedMetadata) {
      vm.assume(params.metadataHash != bytes32(0));
    } else {
      params.metadataHash = bytes32(0);
    }

    test_decodeSignature_packed_vars memory vars;

    string memory base64UrlChallenge = vm.toBase64URL(params.challengeBytes);

    vars.typeValue = generateRandomString(params.typeValueSeed);
    vars.originValue = generateRandomString(params.originValueSeed);

    vars.clientDataJSON = string.concat(
      '{"type":"', vars.typeValue, '","challenge":"', base64UrlChallenge, '","origin":"', vars.originValue, '"}'
    );

    vars.typeIndex = 1;
    vars.challengeIndex = 11 + bytes(vars.typeValue).length;

    vars.pkParams.x = params.x;
    vars.pkParams.y = params.y;
    vars.pkParams.requireUserVerification = params.requireUserVerification;
    if (params.embedMetadata || params.metadataHash != bytes32(0)) {
      vars.pkParams.metadataHash = params.metadataHash;
    }

    vars.sigParams.r = params.r;
    vars.sigParams.s = params.s;
    vars.sigParams.authenticatorData = params.authenticatorData;
    vars.sigParams.clientDataJson = vars.clientDataJSON;

    vars.encodedSignature =
      PrimitivesRPC.passkeysEncodeSignature(vm, vars.pkParams, vars.sigParams, params.embedMetadata);

    (vars.decodedAuth, vars.decodedRUV, vars.decodedX, vars.decodedY, vars.decodedMetadata) =
      passkeysImp.decodeSignaturePub(vars.encodedSignature);

    assertEq(vars.decodedRUV, params.requireUserVerification, "Packed Decoded RUV mismatch");
    assertEq(vars.decodedY, params.y, "Packed Decoded Y mismatch");
    assertEq(vars.decodedX, params.x, "Packed Decoded X mismatch");
    assertEq(
      keccak256(vars.decodedAuth.authenticatorData),
      keccak256(params.authenticatorData),
      "Packed Decoded authenticatorData mismatch"
    );
    assertEq(
      keccak256(bytes(vars.decodedAuth.clientDataJSON)),
      keccak256(bytes(vars.clientDataJSON)),
      "Packed Decoded clientDataJSON mismatch"
    );
    assertEq(vars.decodedAuth.r, params.r, "Packed Decoded R mismatch");
    assertEq(vars.decodedAuth.s, params.s, "Packed Decoded S mismatch");
    assertEq(vars.decodedAuth.challengeIndex, vars.challengeIndex, "Packed Decoded challengeIndex mismatch");
    assertEq(vars.decodedAuth.typeIndex, vars.typeIndex, "Packed Decoded typeIndex mismatch");
    assertEq(vars.decodedMetadata, params.metadataHash, "Packed Decoded metadata mismatch");
  }

  struct test_decodeSignature_abi_params {
    bool requireUserVerification;
    bytes32 x;
    bytes32 y;
    bytes32 r;
    bytes32 s;
    bytes authenticatorData;
    bytes challengeBytes;
    bytes32 metadataHash;
    bool includeMetadata;
    uint256 typeValueSeed;
    uint256 originValueSeed;
  }

  struct test_decodeSignature_abi_vars {
    string clientDataJSON;
    uint256 challengeIndex;
    uint256 typeIndex;
    WebAuthn.WebAuthnAuth authInput;
    bytes encodedTuple;
    bytes1 flagByte;
    bytes encodedSignatureWithFlag;
    WebAuthn.WebAuthnAuth decodedAuth;
    bool decodedRUV;
    bytes32 decodedX;
    bytes32 decodedY;
    bytes32 decodedMetadata;
    string typeValue;
    string originValue;
  }

  // Fuzz test for _decodeSignature using the ABI encoded fallback format
  function test_decodeSignature_abi(
    test_decodeSignature_abi_params memory params
  ) public view {
    // --- Setup & Assumptions ---
    vm.assume(params.authenticatorData.length > 0 && params.authenticatorData.length <= 65535);
    vm.assume(params.challengeBytes.length > 0 && params.challengeBytes.length < 100);
    vm.assume(params.r != bytes32(0));
    vm.assume(params.s != bytes32(0));

    if (params.includeMetadata) {
      vm.assume(params.metadataHash != bytes32(0));
    } else {
      params.metadataHash = bytes32(0);
    }

    test_decodeSignature_abi_vars memory vars;

    string memory base64UrlChallenge = vm.toBase64URL(params.challengeBytes);
    vars.typeValue = generateRandomString(params.typeValueSeed);
    vars.originValue = generateRandomString(params.originValueSeed);

    vars.clientDataJSON = string.concat(
      '{"type":"', vars.typeValue, '","challenge":"', base64UrlChallenge, '","origin":"', vars.originValue, '"}'
    );
    vars.challengeIndex = 11 + bytes(vars.typeValue).length;
    vars.typeIndex = 1;

    // --- ABI Encoding ---
    vars.authInput = WebAuthn.WebAuthnAuth({
      authenticatorData: params.authenticatorData,
      clientDataJSON: vars.clientDataJSON,
      challengeIndex: vars.challengeIndex,
      typeIndex: vars.typeIndex,
      r: params.r,
      s: params.s
    });

    vars.encodedTuple =
      abi.encode(vars.authInput, params.requireUserVerification, params.x, params.y, params.metadataHash);
    vars.flagByte = bytes1(uint8(0x20) | (params.includeMetadata ? uint8(0x40) : uint8(0x00)));
    vars.encodedSignatureWithFlag = abi.encodePacked(vars.flagByte, vars.encodedTuple);

    // --- Contract Decoding ---
    (vars.decodedAuth, vars.decodedRUV, vars.decodedX, vars.decodedY, vars.decodedMetadata) =
      passkeysImp.decodeSignaturePub(vars.encodedSignatureWithFlag);

    // --- Assertions ---
    assertEq(vars.decodedRUV, params.requireUserVerification, "ABI Decoded RUV mismatch");
    assertEq(vars.decodedX, params.x, "ABI Decoded X mismatch");
    assertEq(vars.decodedY, params.y, "ABI Decoded Y mismatch");
    assertEq(
      keccak256(vars.decodedAuth.authenticatorData),
      keccak256(params.authenticatorData),
      "ABI Decoded authenticatorData mismatch"
    );
    assertEq(
      keccak256(bytes(vars.decodedAuth.clientDataJSON)),
      keccak256(bytes(vars.clientDataJSON)),
      "ABI Decoded clientDataJSON mismatch"
    );
    assertEq(vars.decodedAuth.r, params.r, "ABI Decoded R mismatch");
    assertEq(vars.decodedAuth.s, params.s, "ABI Decoded S mismatch");
    assertEq(vars.decodedAuth.challengeIndex, vars.challengeIndex, "ABI Decoded challengeIndex mismatch");
    assertEq(vars.decodedAuth.typeIndex, vars.typeIndex, "ABI Decoded typeIndex mismatch");
    assertEq(vars.decodedMetadata, params.metadataHash, "ABI Decoded metadata mismatch");
  }

}
