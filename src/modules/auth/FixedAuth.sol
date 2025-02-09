// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Wallet } from "../../Wallet.sol";
import { Implementation } from "../Implementation.sol";
import { Storage } from "../Storage.sol";
import { BaseAuth } from "./BaseAuth.sol";

contract FixedAuth is BaseAuth, Implementation {

  bytes32 public immutable INIT_CODE_HASH;
  address public immutable FACTORY;
  address public immutable UPGRADEABLE_IMPLEMENTATION;

  //                        IMAGE_HASH_KEY = keccak256("org.arcadeum.module.auth.upgradable.image.hash");
  bytes32 internal constant IMAGE_HASH_KEY = bytes32(0xea7157fa25e3aa17d0ae2d5280fa4e24d421c61842aa85e45194e1145aa72bf8);

  event ImageHashUpdated(bytes32 newImageHash);

  // Errors
  error ImageHashIsZero();
  error InvalidSignatureType(bytes1 _type);

  constructor(address _factory, address _mainModuleUpgradeable) {
    // Build init code hash of the deployed wallets using that module
    bytes32 initCodeHash = keccak256(abi.encodePacked(Wallet.creationCode, uint256(uint160(address(this)))));

    INIT_CODE_HASH = initCodeHash;
    FACTORY = _factory;
    UPGRADEABLE_IMPLEMENTATION = _mainModuleUpgradeable;
  }

  function _updateImageHash(
    bytes32 _imageHash
  ) internal virtual override {
    // Update imageHash in storage
    if (_imageHash == bytes32(0)) {
      revert ImageHashIsZero();
    }
    Storage.writeBytes32(IMAGE_HASH_KEY, _imageHash);
    emit ImageHashUpdated(_imageHash);

    // Update wallet implementation to mainModuleUpgradeable
    _updateImplementation(UPGRADEABLE_IMPLEMENTATION);
  }

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override returns (bool) {
    return address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", FACTORY, _imageHash, INIT_CODE_HASH)))))
      == address(this);
  }

}
