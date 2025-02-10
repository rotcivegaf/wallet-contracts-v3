// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation, LibAttestation } from "src/extensions/sessions/Attestation.sol";
import {
  IImplicitSessionManager,
  IImplicitSessionManagerSignals
} from "src/extensions/sessions/implicit/IImplicitSessionManager.sol";

import { ISignalsImplicitMode } from "src/extensions/sessions/implicit/ISignalsImplicitMode.sol";
import { ImplicitSessionManager } from "src/extensions/sessions/implicit/ImplicitSessionManager.sol";
import { ISapient, Payload } from "src/modules/interfaces/ISapient.sol";

import { MockImplicitContract } from "../../../mocks/MockImplicitContract.sol";
import { AdvTest } from "../../../utils/TestUtils.sol";

contract MockInvalidImplicitContract is ISignalsImplicitMode {

  function acceptImplicitRequest(
    address,
    Attestation calldata,
    bytes32,
    Payload.Call calldata
  ) external pure returns (bytes32) {
    // Return an incorrect magic value
    return bytes32(0);
  }

}

contract ImplicitSessionManagerTest is AdvTest, IImplicitSessionManagerSignals {

  using LibAttestation for Attestation;

  ImplicitSessionManager public sessionManager;
  MockImplicitContract public mockImplicit;

  uint256 public sessionSignerPk = 1;
  uint256 public globalSignerPk = 2;
  address public sessionSigner;
  address public globalSigner;

  function setUp() public {
    sessionManager = new ImplicitSessionManager();
    mockImplicit = new MockImplicitContract();
    sessionSigner = vm.addr(sessionSignerPk);
    globalSigner = vm.addr(globalSignerPk);

    vm.label(sessionSigner, "sessionSigner");
    vm.label(globalSigner, "globalSigner");
    vm.label(address(sessionManager), "sessionManager");
    vm.label(address(mockImplicit), "mockImplicit");
  }

  /// @notice Verifies that the session manager supports the required interfaces.
  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(IImplicitSessionManager).interfaceId));
  }

  /// @dev Helper to create a Payload.Decoded with one call.
  function _createPayloadWithCall(
    address to,
    bool delegateCall,
    uint256 value,
    bytes memory data
  ) internal pure returns (Payload.Decoded memory payload) {
    Payload.Call memory call = Payload.Call({
      to: to,
      value: value,
      data: data,
      gasLimit: 0,
      delegateCall: delegateCall,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = call;
    payload = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
  }

  /// @dev Helper to create an empty payload (no calls).
  function _createEmptyPayload() internal pure returns (Payload.Decoded memory payload) {
    Payload.Call[] memory calls = new Payload.Call[](0);
    payload = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
  }

  /// @dev Converts a standard (r,s,v) signature to its ERC-2098 compact form.
  function _toERC2098(uint8 v, bytes32 s) internal pure returns (bytes32) {
    uint256 yParity = (v == 28 ? 1 : 0);
    return bytes32((uint256(s) & ((1 << 255) - 1)) | (yParity << 255));
  }

  /// @dev Simple bubble sort for an array of addresses in memory.
  function _sortAddressesMemory(
    address[] memory arr
  ) internal pure returns (address[] memory) {
    uint256 n = arr.length;
    for (uint256 i = 0; i < n; i++) {
      for (uint256 j = 0; j < n - 1; j++) {
        if (arr[j] > arr[j + 1]) {
          address temp = arr[j];
          arr[j] = arr[j + 1];
          arr[j + 1] = temp;
        }
      }
    }
    return arr;
  }

  /// @dev Converts a calldata address array to memory and sorts it.
  function _calldataToMemoryAndSort(
    address[] calldata input
  ) internal pure returns (address[] memory) {
    address[] memory arr = new address[](input.length);
    for (uint256 i = 0; i < input.length; i++) {
      arr[i] = input[i];
    }
    return _sortAddressesMemory(arr);
  }

  /// @dev Helper to encode the implicit session signature.
  /// The encoding format is:
  ///   [session signature (64 bytes)] ++ [packed attestation]
  ///   ++ [global signature (64 bytes)] ++ [uint24(blacklist.length)] ++ [blacklist addresses...]
  function _encodeSignature(
    Payload.Decoded memory payload,
    Attestation memory attestation,
    address[] memory blacklist
  ) internal view returns (bytes memory signature) {
    // 1. Sign the payload using the session key.
    uint8 v1;
    bytes32 r1;
    bytes32 s1;
    bytes32 compactS1;
    {
      bytes32 payloadHash = keccak256(abi.encode(payload));
      (v1, r1, s1) = vm.sign(sessionSignerPk, payloadHash);
      compactS1 = _toERC2098(v1, s1);
    }

    // 2. Sign the attestation using the global key.
    uint8 v2;
    bytes32 r2;
    bytes32 s2;
    bytes32 compactS2;
    {
      bytes32 attestationHash = attestation.toHash();
      (v2, r2, s2) = vm.sign(globalSignerPk, attestationHash);
      compactS2 = _toERC2098(v2, s2);
    }

    // 3. Encode all parts.
    signature = abi.encodePacked(r1, compactS1, attestation.toPacked(), r2, compactS2, uint24(blacklist.length));
    for (uint256 i = 0; i < blacklist.length; i++) {
      signature = abi.encodePacked(signature, blacklist[i]);
    }
  }

  /// @notice Test for a valid implicit session.
  function test_validImplicitSession(
    bytes calldata authData,
    bytes calldata applicationData,
    address[] calldata fuzzBlacklist
  ) public view {
    Payload.Decoded memory payload = _createPayloadWithCall(address(mockImplicit), false, 0, "");
    // For a valid session, none of the blacklist addresses can equal the call target.
    for (uint256 i = 0; i < fuzzBlacklist.length; i++) {
      vm.assume(fuzzBlacklist[i] != address(mockImplicit));
    }
    // Convert and sort the fuzzed blacklist.
    address[] memory blacklist = _calldataToMemoryAndSort(fuzzBlacklist);

    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });

    bytes memory sig = _encodeSignature(payload, attestation, blacklist);
    bytes32 imageHash = sessionManager.isValidSapientSignature(payload, sig);

    // Compute expected global signer.
    bytes32 attestationHash = attestation.toHash();
    (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(globalSignerPk, attestationHash);
    address recoveredGlobal = ecrecover(attestationHash, v2, r2, s2);

    // The expected image hash is keccak256(abi.encode(recoveredGlobal, blacklist)).
    bytes32 expectedHash = keccak256(abi.encode(recoveredGlobal, blacklist));
    assertEq(imageHash, expectedHash, "Image hash mismatch");
  }

  /// @notice Test for delegateCall not allowed.
  function test_delegateCallNotAllowed(bytes calldata authData, bytes calldata applicationData) public {
    Payload.Decoded memory payload = _createPayloadWithCall(
      address(mockImplicit),
      true, // delegateCall enabled -> should revert
      0,
      ""
    );
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    address[] memory emptyBlacklist = new address[](0);
    bytes memory sig = _encodeSignature(payload, attestation, emptyBlacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(InvalidDelegateCall.selector));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for non-zero value not allowed.
  function test_nonZeroValueNotAllowed(
    bytes calldata authData,
    bytes calldata applicationData,
    uint256 nonZeroValue
  ) public {
    vm.assume(nonZeroValue > 0);
    Payload.Decoded memory payload = _createPayloadWithCall(
      address(mockImplicit),
      false,
      nonZeroValue, // non-zero value -> should revert
      ""
    );
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    address[] memory emptyBlacklist = new address[](0);
    bytes memory sig = _encodeSignature(payload, attestation, emptyBlacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(InvalidValue.selector));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for blacklisted address.
  function test_blacklistedAddressNotAllowed(
    bytes calldata authData,
    bytes calldata applicationData,
    address[] calldata fuzzBlacklist
  ) public {
    // Force the blacklist to contain the call target.
    address[] memory blacklist;
    if (fuzzBlacklist.length == 0) {
      blacklist = new address[](1);
      blacklist[0] = address(mockImplicit);
    } else {
      // Copy fuzzBlacklist into memory and force the first element to be the call target.
      blacklist = new address[](fuzzBlacklist.length);
      blacklist[0] = address(mockImplicit);
      for (uint256 i = 1; i < fuzzBlacklist.length; i++) {
        blacklist[i] = fuzzBlacklist[i];
      }
    }
    // Sort the blacklist so that binary search in the contract works correctly.
    blacklist = _sortAddressesMemory(blacklist);

    Payload.Decoded memory payload = _createPayloadWithCall(address(mockImplicit), false, 0, "");
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    bytes memory sig = _encodeSignature(payload, attestation, blacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(BlacklistedAddress.selector, address(mockImplicit)));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for invalid implicit result.
  function test_invalidImplicitResult(bytes calldata authData, bytes calldata applicationData) public {
    // Deploy a contract that returns an incorrect implicit result.
    MockInvalidImplicitContract invalidContract = new MockInvalidImplicitContract();
    vm.label(address(invalidContract), "invalidContract");

    Payload.Decoded memory payload = _createPayloadWithCall(address(invalidContract), false, 0, "");
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    address[] memory emptyBlacklist = new address[](0);
    bytes memory sig = _encodeSignature(payload, attestation, emptyBlacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(InvalidImplicitResult.selector));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for malformed signature.
  function test_malformedSignature(
    bytes calldata randomSig
  ) public {
    Payload.Decoded memory payload = _createEmptyPayload();
    vm.expectRevert();
    sessionManager.isValidSapientSignature(payload, randomSig);
  }

}
