// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { IExplicitSessionManager } from "../../../src/modules/interfaces/IExplicitSessionManager.sol";
import { ISapient } from "../../../src/modules/interfaces/ISapient.sol";
import { ExplicitSessionManager } from "../../../src/modules/sapient/ExplicitSessionManager.sol";

import { AdvTest } from "../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract ExplicitSessionManagerTest is AdvTest {

  ExplicitSessionManager public sessionManager;

  function setUp() public {
    sessionManager = new ExplicitSessionManager();
  }

  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(IExplicitSessionManager).interfaceId));
  }

}
