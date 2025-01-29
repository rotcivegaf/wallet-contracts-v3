// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SessionSig } from "../../../src/modules/sapient/SessionSig.sol";

import { AdvTest } from "../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract SessionSigTest is AdvTest {

  SessionSig public sessionSig;

  function setUp() public {
    sessionSig = new SessionSig();
  }

}
