// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/*

import {Test, Vm} from 'forge-std/Test.sol';

import {SessionSig} from 'src/extensions/sessions/SessionSig.sol';

import {Attestation, LibAttestation} from 'src/extensions/sessions/implicit/Attestation.sol';
import {Payload} from 'src/modules/Payload.sol';

using LibAttestation for Attestation;

contract SessionSigHarness {
  function recover(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) external pure returns (SessionSig.DecodedSignature memory) {
    return SessionSig.recoverSignature(payload, signature);
  }
}

contract SessionSigTest is Test {
  SessionSigHarness internal harness;
  Vm.Wallet internal sessionWallet;
  Vm.Wallet internal globalWallet;

  function setUp() public {
    harness = new SessionSigHarness();
    sessionWallet = vm.createWallet('session');
    globalWallet = vm.createWallet('global');
  }

  // -------------------------------------------------------------------------
  // HELPER FUNCTIONS
  // -------------------------------------------------------------------------

  /// @dev Encodes the explicit config.
  function _encodeExplicitConfig(
    address signer,
    uint256 valueLimit,
    uint256 deadline
  ) internal pure returns (bytes memory) {
    bytes memory node = abi.encodePacked(
      uint8(0), // SessionSig.FLAG_PERMISSIONS
      signer,
      valueLimit,
      deadline,
      uint24(0) // empty permissions array length
    );
    return abi.encodePacked(uint24(node.length), node);
  }

  /// @dev Encodes the implicit config. Here we use an empty blacklist.
  function _encodeImplicitConfig() internal pure returns (bytes memory) {
    return abi.encodePacked(uint24(0));
  }

  /// @dev Signs a hash and encodes the RSV compact signature (r, s, v).
  function _signAndEncodeRSV(
    bytes32 digest,
    Vm.Wallet storage wallet
  ) internal returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, digest);
    return abi.encodePacked(r, s, v);
  }

  /// @dev Helper to build a Payload.Decoded with a given number of calls.
  function _buildPayload(uint256 callCount) internal pure returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.noChainId = true;
    payload.space = 0;
    payload.nonce = 0;
    payload.parentWallets = new address[](0);
    payload.calls = new Payload.Call[](callCount);
  }

  // -------------------------------------------------------------------------
  // TESTS
  // -------------------------------------------------------------------------

  /// @notice Tests the case for an explicit call signature.
  function testExplicitSignature() public {
    Payload.Decoded memory payload = _buildPayload(1);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: 'test',
        gasLimit: 21000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    // Build the encoded signature.
    bytes memory encoded;
    {
      encoded = abi.encodePacked(uint8(0)); // 1. Flags: For explicit calls, inferGlobalSigner flag is false (0).
      encoded = abi.encodePacked(encoded, _encodeExplicitConfig(sessionWallet.addr, 1000, 2000)); // 2. Explicit config
      encoded = abi.encodePacked(encoded, _encodeImplicitConfig()); // 3. Implicit config: empty blacklist.
      // 4. Call signatures: one call. For an explicit call, encode: bool false, then a dummy session permission index (0),
      // then the session signature (RSV compact).
      bytes32 callHash = Payload.hashCall(payload.calls[0]);
      bytes memory sessionSignature = _signAndEncodeRSV(callHash, sessionWallet);
      encoded = abi.encodePacked(encoded, false, uint8(0), sessionSignature);
    }

    // Recover and validate.
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 1, 'Call signatures length');
      SessionSig.CallSignature memory callSig = sig.callSignatures[0];
      assertFalse(callSig.isImplicit, 'Call should be explicit');
      assertEq(callSig.sessionSigner, sessionWallet.addr, 'Recovered session signer');
      assertEq(sig.implicitBlacklist.length, 0, 'Blacklist should be empty');
      assertEq(sig.sessionPermissions.length, 1, 'Session permissions length');
      assertEq(sig.sessionPermissions[0].signer, sessionWallet.addr, 'Session permission signer');
    }
  }
}
*/
