// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../Attestation.sol";
import { Permissions } from "../Permissions.sol";
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
  /// @notice Array of encoded permissions granted to this signer
  Permissions.EncodedPermission[] permissions;
}

interface ISessionManagerSignals {

  /// @notice Invalid signature from session signer
  error InvalidSessionSignature();

  /// @notice Invalid signature from attestation signer
  error InvalidAttestationSignature();

  /// @notice Invalid result from implicit mode
  error InvalidImplicitResult();

  /// @notice Missing required permission for function call
  error MissingPermission(address wallet, address target, bytes4 selector);

  /// @notice Address is blacklisted
  error BlacklistedAddress(address wallet, address target);

  /// @notice Permission limit exceeded
  error PermissionLimitExceeded(address wallet, address target);

  /// @notice Invalid limit usage increment
  error InvalidLimitUsageIncrement();

  /// @notice Missing limit usage increment
  error MissingLimitUsageIncrement();

  /// @notice Invalid delegate call
  error InvalidDelegateCall();

}

interface ISessionManager is ISapient, ISessionManagerSignals {

  /// @notice Increment usage for a caller's given session and target
  /// @param limitUsageHashes Array of hashes of the usage tracking keys, computed as keccak256(abi.encode(wallet, sessionAddr, targetAddr))
  ///                       where wallet is the user's wallet address, sessionAddr is the session signer address,
  ///                       and targetAddr is the target contract address being called
  /// @param usageAmounts Array of amounts to increment the usage counter by for this wallet/session/target combination
  function incrementLimitUsage(bytes32[] calldata limitUsageHashes, uint256[] calldata usageAmounts) external;

}
