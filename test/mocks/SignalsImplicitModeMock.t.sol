// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../../src/modules/Attestation.sol";
import { Payload } from "../../src/modules/Payload.sol";
import { ISignalsImplicitMode } from "../../src/modules/interfaces/ISignalsImplicitMode.sol";

contract SignalsImplicitModeMock is ISignalsImplicitMode {

  // Store expected values for testing
  bytes32 public expectedMagic;
  bytes32 public expectedUrlHash;
  bool public shouldAccept;
  bool public shouldCheckUrlHash;

  // Function to set the expected magic value and acceptance behavior
  function setExpectedResponse(bytes32 _expectedMagic, bool _shouldAccept) external {
    expectedMagic = _expectedMagic;
    shouldAccept = _shouldAccept;
    shouldCheckUrlHash = false;
  }

  // Function to set expected response with URL hash validation
  function setExpectedResponseWithUrl(bytes32 _expectedMagic, bytes32 _expectedUrlHash, bool _shouldAccept) external {
    expectedMagic = _expectedMagic;
    expectedUrlHash = _expectedUrlHash;
    shouldAccept = _shouldAccept;
    shouldCheckUrlHash = true;
  }

  function acceptImplicitRequest(
    address,
    Attestation calldata,
    bytes32 _redirectUrlHash,
    Payload.Call calldata
  ) external view returns (bytes32) {
    // Check URL hash if enabled
    if (shouldCheckUrlHash && _redirectUrlHash != expectedUrlHash) {
      return bytes32(0);
    }

    // If shouldAccept is true, return the expected magic value
    // Otherwise return a different value to simulate rejection
    if (shouldAccept) {
      return expectedMagic;
    } else {
      return bytes32(0);
    }
  }

}
