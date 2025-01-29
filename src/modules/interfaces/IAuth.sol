// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

abstract contract IAuth {

  //                        IMAGE_HASH_KEY = keccak256("org.arcadeum.module.auth.upgradable.image.hash");
  bytes32 internal constant IMAGE_HASH_KEY = bytes32(0xea7157fa25e3aa17d0ae2d5280fa4e24d421c61842aa85e45194e1145aa72bf8);

  event ImageHashUpdated(bytes32 newImageHash);

  // Errors
  error ImageHashIsZero();
  error InvalidSignatureType(bytes1 _type);
  error OnlySelf(address _sender);

  modifier onlySelf() {
    if (msg.sender != address(this)) {
      revert OnlySelf(msg.sender);
    }
    _;
  }

  function signatureValidation(
    Payload.Decoded memory _payload,
    bytes calldata _signature
  ) public view virtual returns (bool isValid, bytes32 subdigest);

  function signatureRecovery(
    Payload.Decoded memory _payload,
    bytes calldata _signature
  )
    public
    view
    virtual
    returns (uint256 threshold, uint256 weight, bytes32 imageHash, bytes32 subdigest, uint256 checkpoint);

  /**
   * @notice Validates the signature image
   * @return true if the signature image is valid
   */
  function _isValidImage(bytes32) internal view virtual returns (bool) {
    return false;
  }

  /**
   * @notice Updates the signers configuration of the wallet
   * @param _imageHash New required image hash of the signature
   */
  function updateImageHash(bytes32 _imageHash) external virtual;

  /**
   * @notice Updates the signers configuration of the wallet
   * @param _imageHash New required image hash of the signature
   */
  function _updateImageHash(bytes32 _imageHash) internal virtual;

}
