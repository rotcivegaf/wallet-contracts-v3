// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Recovery } from "../../../src/extensions/recovery/Recovery.sol";

import { PrimitivesRPC } from "../../utils/PrimitivesRPC.sol";
import { AdvTest } from "../../utils/TestUtils.sol";

contract RecoveryImp is Recovery {

  function recoverBranch(
    address _wallet,
    bytes32 _payloadHash,
    bytes calldata _signature
  ) external view returns (bool verified, bytes32 root) {
    return _recoverBranch(_wallet, _payloadHash, _signature);
  }

}

contract RecoveryTest is AdvTest {

  RecoveryImp public recovery;

  function setUp() public {
    recovery = new RecoveryImp();
  }

  struct Signer {
    address signer;
    uint24 requiredDeltaTime;
    uint64 minTimestamp;
  }

  function test_recoverBranch(Signer[] calldata signers, address wallet, bytes32 payloadHash) public {
    vm.assume(signers.length > 0);

    string memory leaves;

    for (uint256 i = 0; i < signers.length; i++) {
      if (i > 0) {
        leaves = string.concat(leaves, " ");
      }
      leaves = string.concat(
        leaves,
        "signer:",
        vm.toString(signers[i].signer),
        ":",
        vm.toString(signers[i].requiredDeltaTime),
        ":",
        vm.toString(signers[i].minTimestamp)
      );
    }

    bytes32 rpcRoot = PrimitivesRPC.recoveryHashFromLeaves(vm, leaves);
    vm.assume(rpcRoot != bytes32(0));

    bytes memory encoded = PrimitivesRPC.recoveryEncode(vm, leaves);
    bytes32 rpcRootEncoded = PrimitivesRPC.recoveryHashEncoded(vm, encoded);
    assertEq(rpcRoot, rpcRootEncoded);

    (bool verified, bytes32 root) = recovery.recoverBranch(wallet, payloadHash, encoded);
    assertEq(verified, false);
    assertEq(root, rpcRoot);
  }

}
