// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ISapient } from "../src/modules/interfaces/ISapient.sol";
import { ISessionManager, ISessionManagerSignals } from "../src/modules/interfaces/ISessionManager.sol";
import { SessionManager } from "../src/modules/sapient/SessionManager.sol";

import { MockPayableReceiver } from "./mocks/MockPayableReceiver.sol";
import { Test, Vm } from "forge-std/Test.sol";

contract SessionManagerTest is Test, ISessionManagerSignals {

  SessionManager public sessionManager;

  function setUp() public {
    sessionManager = new SessionManager();
  }

  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(ISessionManager).interfaceId));
  }

}
