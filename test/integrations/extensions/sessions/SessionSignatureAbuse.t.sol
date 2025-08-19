// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ExtendedSessionTestBase } from "./ExtendedSessionTestBase.sol";
import { Vm, console } from "forge-std/Test.sol";

import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import {
  SessionErrors, SessionManager, SessionPermissions, SessionSig
} from "src/extensions/sessions/SessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Attestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Calls } from "src/modules/Calls.sol";
import { Payload } from "src/modules/Payload.sol";

/// @notice Session signature abuse tests.
contract IntegrationSessionSignatureAbuseTest is ExtendedSessionTestBase {

  function test_SessionSigner_ZeroAddress_reverts_InvalidSessionSigner(uint8 v, bytes32 s) public {
    // Create a topology with the session signer
    string memory topology = _createDefaultTopology();

    // Create a wallet with the topology
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Build the payload
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0].to = address(mockTarget);

    // Build the signature
    string[] memory callSignatures = new string[](1);
    bytes32 payloadHash = SessionSig.hashCallWithReplayProtection(payload.calls[0], payload);
    bytes32 r = bytes32(0); // Force the signature to return address(0)
    assertEq(ecrecover(payloadHash, v, r, s), address(0));
    callSignatures[0] = _explicitCallSignatureToJSON(
      0, string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)))
    );
    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);
    bytes memory sessionSignatures =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures)));
    bytes memory encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, false);

    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    // Execute
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidSessionSigner.selector, address(0)));
    wallet.execute(packedPayload, encodedSignature);
  }

}
