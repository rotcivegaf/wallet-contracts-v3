// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

contract SelfAuth {

  error OnlySelf(address _sender);

  modifier onlySelf() {
    if (msg.sender != address(this)) {
      revert OnlySelf(msg.sender);
    }
    _;
  }

}
