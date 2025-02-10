// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "../../../../src/extensions/sessions/Permission.sol";
import {
  ImplicitSessionSig,
  ImplicitSessionSignature,
  Payload
} from "../../../../src/extensions/sessions/implicit/ImplicitSessionSig.sol";

import { PrimitivesRPC } from "../../../utils/PrimitivesRPC.sol";
import { AdvTest } from "../../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract ImplicitSessionSigImp is ImplicitSessionSig {

  function recoverSignature(
    Payload.Decoded memory payload,
    bytes calldata signature
  ) external pure returns (ImplicitSessionSignature memory) {
    return _recoverSignature(payload, signature);
  }

}

contract ImplicitSessionSigTest is AdvTest {

  ImplicitSessionSigImp public sessionSig;

  function setUp() public {
    sessionSig = new ImplicitSessionSigImp();
  }

}
