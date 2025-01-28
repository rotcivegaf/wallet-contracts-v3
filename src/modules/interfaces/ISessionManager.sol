// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../Attestation.sol";
import { PermissionValidator } from "../PermissionValidator.sol";
import { Permission, UsageLimit } from "./IPermission.sol";
import { ISapient, Payload } from "./ISapient.sol";

/// @notice Represents a signature for a session, containing all necessary components for validation
struct SessionManagerSignature {
  /// @notice Whether this signature is for an implicit session mode
  bool isImplicit;
  /// @notice Session configuration for the calling wallet including permissions and blacklist
  SessionManagerConfiguration configuration;
  /// @notice The attestation data for the current session
  Attestation attestation;
  /// @notice Signature from the wallet's global signer validating the attestation
  bytes globalSignature;
  /// @notice Signature from the session signer validating the payload
  bytes sessionSignature;
  /// @notice Indices of permissions used for this request
  uint8[] permissionIdxPerCall;
}

/// @notice Configuration for a session manager permissions and blacklist
/// @dev Global signer is inferred from the signature verification
struct SessionManagerConfiguration {
  /// @notice Array of permissions for each session signer, sorted by signer address
  SessionPermissions[] sessionPermissions;
  /// @notice Array of addresses blacklisted from being called in implicit mode, sorted
  address[] implicitBlacklist;
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
