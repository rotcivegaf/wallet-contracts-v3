// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";

contract AdvTest is Test {

  function boundPk(
    uint256 _a
  ) internal pure returns (uint256) {
    _a = bound(_a, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139);
    return _a;
  }

}
