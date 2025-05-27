// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import { IERC1271, IERC1271_MAGIC_VALUE_HASH } from "../../modules/interfaces/IERC1271.sol";
import { IAccount, PackedUserOperation } from "./IAccount.sol";
import { Calls } from "../../modules/Calls.sol";

contract ERC4337Hook is IAccount {

  uint256 internal constant SIG_VALIDATION_FAILED = 1;

  address public immutable entrypoint;

  error InvalidEntrypoint(address _entrypoint);

  constructor(
    address _entrypoint
  ) {
    entrypoint = _entrypoint;
  }

  function validateUserOp(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
  ) external returns (uint256 validationData) {
    if (msg.sender != entrypoint) {
      revert InvalidEntrypoint(msg.sender);
    }

    if (IERC1271(address(this)).isValidSignature(userOpHash, userOp.signature) != IERC1271_MAGIC_VALUE_HASH) {
      return SIG_VALIDATION_FAILED;
    }

    // userOp.nonce is validated by the entrypoint

    if (missingAccountFunds != 0) {
      (bool success,) = payable(msg.sender).call{ value: missingAccountFunds }("");
      (success);
      // Ignore failure (its EntryPoint's job to verify, not account.)
    }

    return 0;
  }

  function executeUserOp(
    bytes calldata _payload
  ) external {
    if (msg.sender != entrypoint) {
      revert InvalidEntrypoint(msg.sender);
    }

    Calls(address(this)).selfExecute(_payload);
  }
}
