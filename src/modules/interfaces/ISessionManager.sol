// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../Attestation.sol";

import { Permission, UsageLimit } from "../Permission.sol";
import { PermissionValidator } from "../sapient/PermissionValidator.sol";
import { ISapient, Payload } from "./ISapient.sol";

/// @notice Represents a signature for a session, containing all necessary components for validation
struct SessionManagerSignature {
  /// @notice Whether this signature is for an implicit session mode
  bool isImplicit;
  /// @notice The attestation data for the current session
  Attestation attestation;
  /// @notice The global signer address
  address globalSigner;
  /// @notice The permissions root for the session in this configuration
  bytes32 permissionsRoot;
  /// @notice Session permissions for the session signer
  SessionPermissions sessionPermissions;
  /// @notice Array of addresses blacklisted from being called in implicit mode, sorted
  address[] implicitBlacklist;
  /// @notice Indices of permissions used for this request
  uint8[] permissionIdxPerCall;
}

/// @notice Permissions configuration for a specific session signer
struct SessionPermissions {
  /// @notice Address of the session signer these permissions apply to
  address signer;
  /// @notice Maximum native token value this signer can send
  uint256 valueLimit;
  /// @notice Deadline for the session. (0 = no deadline)
  uint256 deadline;
  /// @notice Array of encoded permissions granted to this signer
  Permission[] permissions;
}

/// @notice Signals for the session manager
interface ISessionManagerSignals {

  /// @notice Invalid signature from session signer
  error InvalidSessionSignature();

  /// @notice Invalid result from implicit mode
  error InvalidImplicitResult();

  /// @notice Invalid delegate call
  error InvalidDelegateCall();

  /// @notice Invalid value
  error InvalidValue();

  /// @notice Missing permissions for the given signer
  error MissingPermissions(address signer);

  /// @notice Missing required permission for function call
  error MissingPermission(uint256 callIdx);

  /// @notice Invalid permission
  error InvalidPermission(uint256 callIdx);

  /// @notice Missing limit usage increment
  error MissingLimitUsageIncrement();

  /// @notice Invalid limit usage increment
  error InvalidLimitUsageIncrement();

  /// @notice Address is blacklisted
  error BlacklistedAddress(address target);

  /// @notice Session has expired
  error SessionExpired(address sessionSigner, uint256 deadline);

}

interface ISessionManager is ISapient, ISessionManagerSignals {

  /// @notice Increment usage for a caller's given session and target
  /// @param limits Array of limit/session/target combinations
  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external;

}
