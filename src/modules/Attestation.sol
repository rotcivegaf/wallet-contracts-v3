// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX} from "./interfaces/ISignalsImplicitMode.sol";
import {LibBytesPointer} from "../utils/LibBytesPointer.sol";
import {LibOptim} from "../utils/LibOptim.sol";

using LibBytesPointer for bytes;
using LibOptim for bytes;

struct Attestation {
    address _approvedSigner;
    bytes4 _identityType;
    bytes32 _issuerHash;
    bytes32 _audienceHash;
    bytes _authData;
    bytes _applicationData;
}

library LibAttestation {
    function toHash(Attestation memory _attestation) internal pure returns (bytes32) {
        return keccak256(abi.encode(_attestation));
    }

    function generateImplicitRequestMagic(Attestation memory _attestation, address _wallet)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX, _wallet, _attestation._audienceHash, _attestation._issuerHash
            )
        );
    }
}
