// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation } from "../Attestation.sol";
import { Permissions } from "../Permissions.sol";
import { ISapient, Payload } from "./ISapient.sol";

struct SessionSignature {
  bool isImplicit;
  SessionConfiguration sessionConfiguration;
  Attestation attestation;
  bytes globalSignature;
  bytes sessionSignature;
}

struct SessionConfiguration {
  address globalSigner;
  SessionConfigurationPermissions[] sessionPermissions;
  address[] implicitBlacklist;
}

struct SessionConfigurationPermissions {
  address signer; // Explicit signer
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

}

interface ISessionManager is ISapient, ISessionManagerSignals {

  /// @notice Persist usage for a caller's given session and target
  function persistLimitUsage(address sessionAddress, address targetAddress, Payload.Decoded calldata payload) external;

}
