// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ISapient } from "../../../src/modules/interfaces/ISapient.sol";
import { ISessionManager } from "../../../src/modules/interfaces/ISessionManager.sol";
import { SessionManager } from "../../../src/modules/sapient/SessionManager.sol";

import { AdvTest } from "../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract SessionManagerTest is AdvTest {

  SessionManager public sessionManager;

  function setUp() public {
    sessionManager = new SessionManager();
  }

  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(ISessionManager).interfaceId));
  }

}
