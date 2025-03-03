// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SingletonDeployer, console } from "erc2470-libs/script/SingletonDeployer.s.sol";
import { MockImplicitContract, MockInvalidImplicitContract } from "test/mocks/MockImplicitContract.sol";

contract Deploy is SingletonDeployer {

  function run() external {
    uint256 pk = vm.envUint("PRIVATE_KEY");

    bytes32 salt = bytes32(0);

    bytes memory initCode = abi.encodePacked(type(MockImplicitContract).creationCode);
    _deployIfNotAlready("MockImplicitContract", initCode, salt, pk);

    initCode = abi.encodePacked(type(MockInvalidImplicitContract).creationCode);
    _deployIfNotAlready("MockInvalidImplicitContract", initCode, salt, pk);
  }

}
