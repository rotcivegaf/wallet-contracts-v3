// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

library SessionErrors {

  /// @notice Invalid session signer
  error InvalidSessionSigner(address invalidSigner);
  /// @notice Invalid self call
  error InvalidSelfCall();
  /// @notice Invalid delegate call
  error InvalidDelegateCall();
  /// @notice Invalid value
  error InvalidValue();

  // ---- Explicit session errors ----

  /// @notice Missing permission for explicit session
  error MissingPermission();
  /// @notice Invalid permission for explicit session
  error InvalidPermission();
  /// @notice Session expired
  error SessionExpired(uint256 deadline);
  /// @notice Invalid limit usage increment
  error InvalidLimitUsageIncrement();

  // ---- Implicit session errors ----

  /// @notice Blacklisted address
  error BlacklistedAddress(address target);
  /// @notice Invalid implicit result
  error InvalidImplicitResult();

}
