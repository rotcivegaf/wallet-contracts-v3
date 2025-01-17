// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "./Payload.sol";
import { IAuth } from "./interfaces/IAuth.sol";

abstract contract Calls is IAuth {

  event Success(bytes32 _opHash, uint256 _index);
  event Failed(bytes32 _opHash, uint256 _index);
  event Aborted(bytes32 _opHash, uint256 _index);
  event Skipped(bytes32 _opHash, uint256 _index);

  error Reverted(Payload.Decoded _payload, uint256 _index, bytes _returnData);
  error InvalidSignature(Payload.Decoded _payload, bytes _signature);
  error NotEnoughGas(Payload.Decoded _payload, uint256 _index, uint256 _gasLeft);

  function execute(bytes calldata _payload, bytes calldata _signature) external virtual {
    Payload.Decoded memory decoded = Payload.fromPackedCalls(_payload);
    (bool isValid, bytes32 opHash) = signatureValidation(decoded, _signature);

    if (!isValid) {
      revert InvalidSignature(decoded, _signature);
    }

    _execute(opHash, decoded);
  }

  function selfExecute(
    bytes calldata _payload
  ) external virtual onlySelf {
    Payload.Decoded memory decoded = Payload.fromPackedCalls(_payload);
    bytes32 opHash = Payload.toEIP712(decoded);
    _execute(opHash, decoded);
  }

  function _execute(bytes32 _opHash, Payload.Decoded memory _decoded) private {
    bool errorFlag = false;

    uint256 numCalls = _decoded.calls.length;
    for (uint256 i = 0; i < numCalls; i++) {
      Payload.Call memory call = _decoded.calls[i];

      // If the call is of fallback kind, and errorFlag is set to false
      // then we can skip the call
      if (call.to == address(this) && !errorFlag) {
        errorFlag = false;
        emit Skipped(_opHash, i);
        continue;
      }

      uint256 gasLimit = call.gasLimit;
      if (gasLimit != 0 && gasleft() < gasLimit) {
        revert NotEnoughGas(_decoded, i, gasleft());
      }

      // TODO: Copy return data only if needed
      bytes memory returnData;
      bool success;
      if (call.delegateCall) {
        (success, returnData) = call.to.delegatecall{ gas: gasLimit }(call.data);
      } else {
        (success, returnData) = call.to.call{ value: call.value, gas: gasLimit }(call.data);
      }

      if (!success) {
        if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
          errorFlag = true;
          emit Failed(_opHash, i);
          continue;
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_REVERT_ON_ERROR) {
          revert Reverted(_decoded, i, returnData);
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_ABORT_ON_ERROR) {
          emit Aborted(_opHash, i);
          break;
        }
      }

      emit Success(_opHash, i);
    }
  }

}
