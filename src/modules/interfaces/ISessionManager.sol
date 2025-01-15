// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ISapient, Payload} from "./ISapient.sol";
import {Permissions} from "../Permissions.sol";
import {Attestation} from "../Attestation.sol";

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
}

interface ISessionManager is ISapient, ISessionManagerSignals {}
