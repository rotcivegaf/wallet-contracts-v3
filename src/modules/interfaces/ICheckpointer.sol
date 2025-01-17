// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

struct Snapshot {
  bytes32 imageHash;
  uint256 checkpoint;
}

interface ICheckpointer {

  function snapshotFor(address _wallet, bytes calldata _proof) external view returns (Snapshot memory);

}
