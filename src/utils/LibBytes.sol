// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @title Library for reading data from bytes arrays
 * @author Agustin Aguilar (aa@horizon.io), Michael Standen (mstan@horizon.io)
 * @notice This library contains functions for reading data from bytes arrays.
 *
 * @dev These functions do not check if the input index is within the bounds of the data array.
 *         Reading out of bounds may return dirty values.
 */
library LibBytes {

  /**
   * @notice Returns the uint8 value at the given index in the input data.
   * @param data The input data.
   * @param index The index of the value to retrieve.
   * @return a The uint8 value at the given index.
   */
  function readUint8(bytes calldata data, uint256 index) internal pure returns (uint8 a) {
    assembly {
      let word := calldataload(add(index, data.offset))
      a := shr(248, word)
    }
  }

  /**
   * @notice Returns the bytes32 value at the given index in the input data.
   * @param data The input data.
   * @param index The index of the value to retrieve.
   * @return a The bytes32 value at the given index.
   */
  function readBytes32(bytes calldata data, uint256 index) internal pure returns (bytes32 a) {
    assembly {
      a := calldataload(add(data.offset, index))
    }
  }

  // ERC-2098 Compact Signature
  function readRSVCompact(bytes calldata data, uint256 index) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
    uint256 yParityAndS;
    assembly {
      let offset := data.offset
      r := calldataload(add(offset, index))
      yParityAndS := calldataload(add(offset, add(index, 32)))
    }
    uint256 yParity = uint256(yParityAndS >> 255);
    s = bytes32(uint256(yParityAndS) & ((1 << 255) - 1));
    v = uint8(yParity) + 27;
  }

}
