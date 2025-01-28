// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../Attestation.sol";

import { PermissionValidator } from "../PermissionValidator.sol";
import { Permission, UsageLimit } from "./IPermission.sol";
import { ISapient, Payload } from "./ISapient.sol";

/// @notice Represents a signature for a session, containing all necessary components for validation
/// @dev Used to validate both implicit and explicit session modes
struct SessionSignature {
  /// @notice Whether this signature is for an implicit session mode
  bool isImplicit;
  /// @notice Session configuration for the calling wallet including permissions and blacklist
  SessionConfiguration sessionConfiguration;
  /// @notice The attestation data for the current session
  Attestation attestation;
  /// @notice Signature from the wallet's global signer validating the attestation
  bytes globalSignature;
  /// @notice Signature from the session signer validating the payload
  bytes sessionSignature;
  /// @notice Indices of permissions used for this request, mapping to sessionConfiguration.sessionPermissions
  /// @dev TODO Confirm this optimises the signature verification by only including the permissions used in the request
  uint8[] permissionIdxPerCall;
}

/// @notice Configuration for a session defining permissions and blacklist
/// @dev Global signer is inferred from the signature verification
struct SessionConfiguration {
  /// @notice Array of permissions for each session signer, sorted by signer address
  SessionConfigurationPermissions[] sessionPermissions;
  /// @notice Array of addresses blacklisted from being called in implicit mode, sorted
  address[] implicitBlacklist;
}

/// @notice Permissions configuration for a specific session signer
struct SessionConfigurationPermissions {
  /// @notice Address of the session signer these permissions apply to
  address signer;
  /// @notice Maximum native token value this signer can send
  uint256 valueLimit;
  /// @notice Deadline for the session. (0 = no deadline)
  uint256 deadline;
  /// @notice Array of encoded permissions granted to this signer
  Permission[] permissions;
}

interface ISessionManagerSignals {

  //FIXME Tidy these errors

  /// @notice Invalid signature from session signer
  error InvalidSessionSignature();

  /// @notice Invalid signature from attestation signer
  error InvalidAttestationSignature();

  /// @notice Invalid result from implicit mode
  error InvalidImplicitResult();

  /// @notice Invalid value
  error InvalidValue();

  /// @notice Missing required permission for function call
  error MissingPermission(address target, bytes4 selector);

  /// @notice Invalid permission
  error InvalidPermission(address target, bytes4 selector);

  /// @notice Permission limit exceeded
  error UsageLimitExceeded(address wallet, address target);

  /// @notice Invalid limit usage increment
  error InvalidLimitUsageIncrement();

  /// @notice Missing limit usage increment
  error MissingLimitUsageIncrement();

  /// @notice Address is blacklisted
  error BlacklistedAddress(address wallet, address target);

  /// @notice Invalid delegate call
  error InvalidDelegateCall();

  /// @notice Session has expired
  error SessionExpired(address wallet, address sessionSigner);

}

interface ISessionManager is ISapient, ISessionManagerSignals {

  /// @notice Increment usage for a caller's given session and target
  /// @param limits Array of limit/session/target combinations
  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external;

}
