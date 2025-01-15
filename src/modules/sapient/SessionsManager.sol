// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ISessionManager, SessionSignature, SessionConfiguration, SessionConfigurationPermissions} from "../interfaces/ISessionManager.sol";
import {Permissions} from "../Permissions.sol";
import {ISapient, Payload} from "../interfaces/ISapient.sol";
import {Attestation, LibAttestation} from "../Attestation.sol";
import {LibBytesPointer} from "../../utils/LibBytesPointer.sol";
import {LibBytes} from "../../utils/LibBytes.sol";
import {ISignalsImplicitMode} from "../interfaces/ISignalsImplicitMode.sol";

using LibBytesPointer for bytes;
using LibBytes for bytes;
using LibAttestation for Attestation;

contract SessionsManager is ISessionManager {
    function isValidSapientSignature(
        Payload.Decoded calldata _payload,
        bytes calldata _encodedSignature
    ) external view returns (bytes32) {
        address wallet = msg.sender;

        // Recover the session signer from the session signature
        bytes32 payloadHash = keccak256(abi.encode(_payload));
        SessionSignature memory signature = abi.decode(
            _encodedSignature,
            (SessionSignature)
        );
        (bytes32 r, bytes32 s, uint8 v) = signature.sessionSignature.readMRSV(
            0
        );
        address recoveredPayloadSigner = ecrecover(payloadHash, v, r, s); // This is the session signer

        // Verify global signer's signature on the attestation
        bytes32 attestationHash = signature.attestation.toHash();
        (r, s, v) = signature.globalSignature.readMRSV(0);
        address recoveredGlobalSigner = ecrecover(attestationHash, v, r, s);
        if (
            recoveredGlobalSigner != signature.sessionConfiguration.globalSigner
        ) {
            revert InvalidAttestationSignature();
        }

        _validateSession(wallet, signature, _payload, recoveredPayloadSigner);

        // Generate and return imageHash
        return keccak256(abi.encode(signature.sessionConfiguration));
    }

    function _validateSession(
        address wallet,
        SessionSignature memory signature,
        Payload.Decoded calldata _payload,
        address recoveredPayloadSigner
    ) internal view {
        // Continue with existing validation
        if (signature.isImplicit) {
            _validateImplicitMode(
                wallet,
                signature,
                _payload,
                recoveredPayloadSigner
            );
        } else {
            _validateExplicitMode(
                wallet,
                signature,
                _payload,
                recoveredPayloadSigner
            );
        }
    }

    function _validateExplicitMode(
        address wallet,
        SessionSignature memory signature,
        Payload.Decoded calldata _payload,
        address recoveredPayloadSigner
    ) internal pure {
        SessionConfigurationPermissions[] memory sessionPermissions = signature
            .sessionConfiguration
            .sessionPermissions;

        // Binary search to find matching permissions for the signer
        uint256 left = 0;
        uint256 right = sessionPermissions.length - 1;
        Permissions.EncodedPermission[] memory permissions;
        while (left <= right) {
            uint256 mid = left + (right - left) / 2;
            address currentSigner = sessionPermissions[mid].signer;
            if (currentSigner == recoveredPayloadSigner) {
                permissions = sessionPermissions[mid].permissions;
                break;
            } else if (currentSigner < recoveredPayloadSigner) {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        // Validate permissions for all calls in the payload
        for (uint256 i = 0; i < _payload.calls.length; i++) {
            bool isPermissionValid = false;
            for (uint256 j = 0; j < permissions.length; j++) {
                if (
                    Permissions.validatePermission(
                        permissions[j],
                        _payload.calls[i]
                    )
                ) {
                    isPermissionValid = true;
                    break;
                }
            }
            if (!isPermissionValid) {
                revert MissingPermission(
                    wallet,
                    _payload.calls[i].to,
                    bytes4(_payload.calls[i].data)
                );
            }
        }
    }

    function _validateImplicitMode(
        address wallet,
        SessionSignature memory signature,
        Payload.Decoded calldata _payload,
        address recoveredPayloadSigner
    ) internal view {
        // Validate the session signer
        if (recoveredPayloadSigner != signature.attestation._approvedSigner) {
            revert InvalidSessionSignature();
        }

        // Validate blacklist
        address[] memory blacklist = signature
            .sessionConfiguration
            .implicitBlacklist;

        // Check each call's target address against blacklist
        for (uint256 i = 0; i < _payload.calls.length; i++) {
            if (_isAddressBlacklisted(_payload.calls[i].to, blacklist)) {
                revert BlacklistedAddress(wallet, _payload.calls[i].to);
            }
        }

        bytes32 attestationMagic = signature
            .attestation
            .generateImplicitRequestMagic(wallet);
        bytes32 redirectUrlHash = keccak256(
            abi.encodePacked(signature.attestation._authData)
        );

        for (uint256 i = 0; i < _payload.calls.length; i++) {
            // Validate implicit mode
            bytes32 result = ISignalsImplicitMode(_payload.calls[i].to)
                .acceptImplicitRequest(
                    wallet,
                    signature.attestation,
                    redirectUrlHash,
                    _payload.calls[i]
                );
            if (result != attestationMagic) {
                revert InvalidImplicitResult();
            }
        }
    }

    // New helper function for binary search in blacklist
    function _isAddressBlacklisted(
        address target,
        address[] memory blacklist
    ) internal pure returns (bool) {
        int256 left = 0;
        int256 right = int256(blacklist.length) - 1;

        while (left <= right) {
            int256 mid = left + (right - left) / 2;
            address currentAddress = blacklist[uint256(mid)];

            if (currentAddress == target) {
                return true;
            } else if (currentAddress < target) {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        return false;
    }

    /// @notice Returns true if the contract implements the given interface
    /// @param interfaceId The interface identifier
    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return
            interfaceId == type(ISapient).interfaceId ||
            interfaceId == type(ISessionManager).interfaceId;
    }
}
