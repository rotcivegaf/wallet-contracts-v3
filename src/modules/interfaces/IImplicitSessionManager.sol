// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../Attestation.sol";

import { Permission, UsageLimit } from "../Permission.sol";
import { PermissionValidator } from "../sapient/PermissionValidator.sol";
import { ISapient, Payload } from "./ISapient.sol";

/// @notice Represents a decoded signature for an implicit session
struct ImplicitSessionSignature {
  /// @notice The attestation data for the current session
  Attestation attestation;
  /// @notice The global signer address
  address globalSigner;
  /// @notice Array of addresses blacklisted from being called in implicit mode, sorted
  address[] implicitBlacklist;
}

/// @notice Signals for the session manager
interface IImplicitSessionManagerSignals {

  /// @notice Invalid signature from session signer
  error InvalidSessionSignature();

  /// @notice Invalid result from implicit mode
  error InvalidImplicitResult();

  /// @notice Invalid delegate call
  error InvalidDelegateCall();

  /// @notice Invalid value
  error InvalidValue();

  /// @notice Address is blacklisted
  error BlacklistedAddress(address target);

  /// @notice Session has expired
  error SessionExpired(uint256 deadline);

}

interface IImplicitSessionManager is ISapient, IImplicitSessionManagerSignals { }
