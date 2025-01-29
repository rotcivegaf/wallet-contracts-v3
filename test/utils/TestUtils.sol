// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import "forge-std/Test.sol";

contract AdvTest is Test {

  function boundPk(
    uint256 _a
  ) internal pure returns (uint256) {
    _a = bound(_a, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139);
    return _a;
  }

  function boundToLegalPayload(
    Payload.Decoded memory _payload
  ) internal pure {
    _payload.kind = uint8(bound(_payload.kind, uint8(0), uint8(Payload.KIND_DIGEST)));

    if (_payload.kind == Payload.KIND_TRANSACTIONS) {
      _payload.space = bound(_payload.space, 0, type(uint56).max);
      _payload.nonce = bound(_payload.nonce, 0, type(uint160).max);

      for (uint256 i = 0; i < _payload.calls.length; i++) {
        _payload.calls[i].behaviorOnError = bound(
          _payload.calls[i].behaviorOnError,
          uint256(Payload.BEHAVIOR_IGNORE_ERROR),
          uint256(Payload.BEHAVIOR_ABORT_ON_ERROR)
        );
      }
    }
  }

}
