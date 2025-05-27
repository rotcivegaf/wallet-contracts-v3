// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

/// @title IPartialAuth
/// @author Agustin Aguilar
/// @notice Interface for the partial auth module
interface IPartialAuth {

  /// @notice Recover the partial signature
  /// @param _payload The payload
  /// @param _signature The signature
  /// @return threshold The threshold
  /// @return weight The weight
  /// @return isValidImage The validity of the image
  /// @return imageHash The image hash
  /// @return checkpoint The checkpoint
  /// @return opHash The operation hash
  function recoverPartialSignature(
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  )
    external
    view
    returns (
      uint256 threshold,
      uint256 weight,
      bool isValidImage,
      bytes32 imageHash,
      uint256 checkpoint,
      bytes32 opHash
    );

}
