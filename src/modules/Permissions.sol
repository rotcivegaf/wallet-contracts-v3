// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Payload} from "./interfaces/ISapient.sol";

library Permissions {
    /// @notice Permission types for different token standards and actions
    enum PermissionType {
        FUNCTION_CALL,
        ERC20_TRANSFER,
        ERC721_TRANSFER,
        ERC1155_TRANSFER
    }

    /// @notice Base permission fields common to all types
    struct BasePermission {
        PermissionType pType;
        address target;
        bytes4 selector;
    }

    /// @notice Permission types and their encoded data
    struct EncodedPermission {
        PermissionType pType;
        bytes data;
    }

    /// @notice Permission for basic function calls
    struct FunctionCallPermission {
        BasePermission base;
    }

    /// @notice Permission for ERC20 transfers with amount limits
    struct ERC20Permission {
        BasePermission base;
        uint256 amountLimit;
        uint256 used;
    }

    /// @notice Permission for ERC721 transfers of specific tokens
    struct ERC721Permission {
        BasePermission base;
        uint256 tokenId;
    }

    /// @notice Permission for ERC1155 transfers with amount limits per token
    struct ERC1155Permission {
        BasePermission base;
        uint256 tokenId;
        uint256 amountLimit;
        uint256 used;
    }

    /// @notice Encodes a function call permission
    function encodeFunctionCall(address _target, bytes4 _selector) internal pure returns (EncodedPermission memory) {
        BasePermission memory base =
            BasePermission({pType: PermissionType.FUNCTION_CALL, target: _target, selector: _selector});
        return EncodedPermission({
            pType: PermissionType.FUNCTION_CALL,
            data: abi.encode(FunctionCallPermission({base: base}))
        });
    }

    /// @notice Encodes an ERC20 permission
    function encodeERC20(address _token, bytes4 _selector, uint256 _amountLimit)
        internal
        pure
        returns (EncodedPermission memory)
    {
        BasePermission memory base =
            BasePermission({pType: PermissionType.ERC20_TRANSFER, target: _token, selector: _selector});
        return EncodedPermission({
            pType: PermissionType.ERC20_TRANSFER,
            data: abi.encode(ERC20Permission({base: base, amountLimit: _amountLimit, used: 0}))
        });
    }

    /// @notice Encodes an ERC721 permission
    function encodeERC721(address _token, bytes4 _selector, uint256 _tokenId)
        internal
        pure
        returns (EncodedPermission memory)
    {
        BasePermission memory base =
            BasePermission({pType: PermissionType.ERC721_TRANSFER, target: _token, selector: _selector});
        return EncodedPermission({
            pType: PermissionType.ERC721_TRANSFER,
            data: abi.encode(ERC721Permission({base: base, tokenId: _tokenId}))
        });
    }

    /// @notice Encodes an ERC1155 permission
    function encodeERC1155(address _token, bytes4 _selector, uint256 _tokenId, uint256 _amountLimit)
        internal
        pure
        returns (EncodedPermission memory)
    {
        BasePermission memory base =
            BasePermission({pType: PermissionType.ERC1155_TRANSFER, target: _token, selector: _selector});
        return EncodedPermission({
            pType: PermissionType.ERC1155_TRANSFER,
            data: abi.encode(ERC1155Permission({base: base, tokenId: _tokenId, amountLimit: _amountLimit, used: 0}))
        });
    }

    /// @notice Validates a permission against a call
    function validatePermission(EncodedPermission memory _permission, Payload.Call calldata _call)
        internal
        pure
        returns (bool)
    {
        if (_permission.pType == PermissionType.FUNCTION_CALL) {
            FunctionCallPermission memory fp = abi.decode(_permission.data, (FunctionCallPermission));
            return validateFunctionCall(fp, _call);
        } else if (_permission.pType == PermissionType.ERC20_TRANSFER) {
            ERC20Permission memory ep = abi.decode(_permission.data, (ERC20Permission));
            return validateERC20(ep, _call);
        } else if (_permission.pType == PermissionType.ERC721_TRANSFER) {
            ERC721Permission memory ep = abi.decode(_permission.data, (ERC721Permission));
            return validateERC721(ep, _call);
        } else if (_permission.pType == PermissionType.ERC1155_TRANSFER) {
            ERC1155Permission memory ep = abi.decode(_permission.data, (ERC1155Permission));
            return validateERC1155(ep, _call);
        }
        return false;
    }

    /// @notice Validates a function call permission
    function validateFunctionCall(FunctionCallPermission memory _permission, Payload.Call calldata _call)
        internal
        pure
        returns (bool)
    {
        return _permission.base.target == _call.to && _permission.base.selector == bytes4(_call.data);
    }

    /// @notice Validates an ERC20 transfer permission
    function validateERC20(ERC20Permission memory _permission, Payload.Call calldata _call)
        internal
        pure
        returns (bool)
    {
        if (_permission.base.target != _call.to || _permission.base.selector != bytes4(_call.data)) {
            return false;
        }

        // Decode transfer parameters
        (, uint256 amount) = abi.decode(_call.data[4:], (address, uint256));
        return amount <= _permission.amountLimit - _permission.used;
    }

    /// @notice Validates an ERC721 transfer permission
    function validateERC721(ERC721Permission memory _permission, Payload.Call calldata _call)
        internal
        pure
        returns (bool)
    {
        if (_permission.base.target != _call.to || _permission.base.selector != bytes4(_call.data)) {
            return false;
        }

        // Decode transfer parameters
        (, uint256 tokenId) = abi.decode(_call.data[4:], (address, uint256));
        return tokenId == _permission.tokenId;
    }

    /// @notice Validates an ERC1155 transfer permission
    function validateERC1155(ERC1155Permission memory _permission, Payload.Call calldata _call)
        internal
        pure
        returns (bool)
    {
        if (_permission.base.target != _call.to || _permission.base.selector != bytes4(_call.data)) {
            return false;
        }

        // Decode transfer parameters
        (, uint256 tokenId, uint256 amount) = abi.decode(_call.data[4:], (address, uint256, uint256));
        return tokenId == _permission.tokenId && amount <= _permission.amountLimit - _permission.used;
    }
}
