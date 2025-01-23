// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../utils/LibBytes.sol";
import { IPermissionValidator } from "./interfaces/IPermissionValidator.sol";
import { Payload } from "./interfaces/ISapient.sol";

library Permissions {

  using LibBytes for bytes;

  /// @notice Permission types supported by the system
  enum PermissionType {
    FUNCTION_CALL,
    NATIVE,
    ERC20,
    ERC721,
    ERC1155,
    RULES,
    REMOTE
  }

  /// @notice Permission for basic function calls
  struct FunctionCallPermission {
    PermissionType pType;
    address target;
    bytes4 selector;
  }

  /// @notice Permission for native token transfers
  struct NativeTransferPermission {
    PermissionType pType;
    uint256 limit;
  }

  /// @notice Permission for ERC20 transfers with amount limits
  struct ERC20Permission {
    PermissionType pType;
    address target;
    uint256 limit;
  }

  /// @notice Permission for ERC721 transfers of specific tokens
  struct ERC721Permission {
    PermissionType pType;
    address target;
    uint256 tokenId;
  }

  /// @notice Permission for ERC1155 transfers with amount limits per token
  struct ERC1155Permission {
    PermissionType pType;
    address target;
    uint256 tokenId;
    uint256 limit;
  }

  /// @notice Permission for rules
  struct RulesPermission {
    PermissionType pType;
    address target;
    ParameterRule[] rules;
  }

  enum ParameterRuleOperation {
    EQUAL,
    NOT_EQUAL,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN_OR_EQUAL
  }

  struct ParameterRule {
    ParameterRuleOperation operation;
    bytes32 value; // Any value encoded as a bytes32
    uint256 offset; // The offset of the parameter in the call data
    bytes32 mask; // The mask to apply to the parameter
  }

  /// @notice Permission for remote validation through external contract
  struct RemotePermission {
    PermissionType pType;
    address validator;
    bytes data;
  }

  /// @notice Permission types and their encoded data
  struct EncodedPermission {
    PermissionType pType;
    bytes data;
  }

  /// @notice Encodes a function call permission
  function encodeFunctionCall(address _target, bytes4 _selector) internal pure returns (EncodedPermission memory) {
    return EncodedPermission({
      pType: PermissionType.FUNCTION_CALL,
      data: abi.encode(
        FunctionCallPermission({ pType: PermissionType.FUNCTION_CALL, target: _target, selector: _selector })
      )
    });
  }

  /// @notice Encodes a native token transfer permission
  function encodeNativeTransfer(
    uint256 _limit
  ) internal pure returns (EncodedPermission memory) {
    return EncodedPermission({
      pType: PermissionType.NATIVE,
      data: abi.encode(NativeTransferPermission({ pType: PermissionType.NATIVE, limit: _limit }))
    });
  }

  /// @notice Encodes an ERC20 permission
  function encodeERC20(address _token, uint256 _amountLimit) internal pure returns (EncodedPermission memory) {
    return EncodedPermission({
      pType: PermissionType.ERC20,
      data: abi.encode(ERC20Permission({ pType: PermissionType.ERC20, target: _token, limit: _amountLimit }))
    });
  }

  /// @notice Encodes an ERC721 permission
  function encodeERC721(address _token, uint256 _tokenId) internal pure returns (EncodedPermission memory) {
    return EncodedPermission({
      pType: PermissionType.ERC721,
      data: abi.encode(ERC721Permission({ pType: PermissionType.ERC721, target: _token, tokenId: _tokenId }))
    });
  }

  /// @notice Encodes an ERC1155 permission
  function encodeERC1155(
    address _token,
    uint256 _tokenId,
    uint256 _amountLimit
  ) internal pure returns (EncodedPermission memory) {
    return EncodedPermission({
      pType: PermissionType.ERC1155,
      data: abi.encode(
        ERC1155Permission({ pType: PermissionType.ERC1155, target: _token, tokenId: _tokenId, limit: _amountLimit })
      )
    });
  }

  /// @notice Encodes a remote permission
  function encodeRemote(address _validator, bytes memory _data) internal pure returns (EncodedPermission memory) {
    return EncodedPermission({
      pType: PermissionType.REMOTE,
      data: abi.encode(RemotePermission({ pType: PermissionType.REMOTE, validator: _validator, data: _data }))
    });
  }

  /// @notice Encodes a rules permission
  function encodeRules(address _target, ParameterRule[] memory _rules) internal pure returns (EncodedPermission memory) {
    return EncodedPermission({
      pType: PermissionType.RULES,
      data: abi.encode(RulesPermission({ pType: PermissionType.RULES, target: _target, rules: _rules }))
    });
  }

  /// @notice Validates a permission against a call
  function validatePermission(
    EncodedPermission memory _permission,
    Payload.Call calldata _call
  ) internal view returns (bool) {
    if (_permission.pType == PermissionType.FUNCTION_CALL) {
      FunctionCallPermission memory fp = abi.decode(_permission.data, (FunctionCallPermission));
      return validateFunctionCall(fp, _call);
    } else if (_permission.pType == PermissionType.NATIVE) {
      NativeTransferPermission memory ep = abi.decode(_permission.data, (NativeTransferPermission));
      return validateNativeTransfer(ep, _call);
    } else if (_permission.pType == PermissionType.ERC20) {
      ERC20Permission memory ep = abi.decode(_permission.data, (ERC20Permission));
      return validateERC20(ep, _call);
    } else if (_permission.pType == PermissionType.ERC721) {
      ERC721Permission memory ep = abi.decode(_permission.data, (ERC721Permission));
      return validateERC721(ep, _call);
    } else if (_permission.pType == PermissionType.ERC1155) {
      ERC1155Permission memory ep = abi.decode(_permission.data, (ERC1155Permission));
      return validateERC1155(ep, _call);
    } else if (_permission.pType == PermissionType.REMOTE) {
      RemotePermission memory rp = abi.decode(_permission.data, (RemotePermission));
      return validateRemote(rp, _call);
    } else if (_permission.pType == PermissionType.RULES) {
      RulesPermission memory rp = abi.decode(_permission.data, (RulesPermission));
      return validateRules(rp, _call);
    }
    return false;
  }

  /// @notice Validates a function call permission
  function validateFunctionCall(
    FunctionCallPermission memory _permission,
    Payload.Call calldata _call
  ) internal pure returns (bool) {
    return _permission.target == _call.to && _permission.selector == bytes4(_call.data);
  }

  function validateNativeTransfer(
    NativeTransferPermission memory _permission,
    Payload.Call calldata _call
  ) internal pure returns (bool) {
    // Validate no call data
    if (_call.data.length > 0) {
      return false;
    }
    return _call.value <= _permission.limit;
  }

  /// @notice Validates an ERC20 transfer permission
  function validateERC20(ERC20Permission memory _permission, Payload.Call calldata _call) internal pure returns (bool) {
    if (_permission.target != _call.to) {
      return false;
    }

    bytes4 selector = bytes4(_call.data);

    // Handle different function calls
    if (selector == bytes4(keccak256("transfer(address,uint256)"))) {
      (, uint256 amount) = abi.decode(_call.data[4:], (address, uint256));
      return amount <= _permission.limit;
    } else if (selector == bytes4(keccak256("transferFrom(address,address,uint256)"))) {
      (,, uint256 amount) = abi.decode(_call.data[4:], (address, address, uint256));
      return amount <= _permission.limit;
    } else if (selector == bytes4(keccak256("approve(address,uint256)"))) {
      (, uint256 amount) = abi.decode(_call.data[4:], (address, uint256));
      return amount <= _permission.limit;
    }
    return false;
  }

  /// @notice Validates an ERC721 transfer permission
  function validateERC721(
    ERC721Permission memory _permission,
    Payload.Call calldata _call
  ) internal pure returns (bool) {
    if (_permission.target != _call.to) {
      return false;
    }

    bytes4 selector = bytes4(_call.data);

    // Handle different function calls
    if (
      selector == bytes4(keccak256("transferFrom(address,address,uint256)"))
        || selector == bytes4(keccak256("safeTransferFrom(address,address,uint256)"))
    ) {
      (,, uint256 tokenId) = abi.decode(_call.data[4:], (address, address, uint256));
      return tokenId == _permission.tokenId;
    } else if (selector == bytes4(keccak256("approve(address,uint256)"))) {
      (, uint256 tokenId) = abi.decode(_call.data[4:], (address, uint256));
      return tokenId == _permission.tokenId;
    }
    return false;
  }

  /// @notice Validates an ERC1155 transfer permission
  function validateERC1155(
    ERC1155Permission memory _permission,
    Payload.Call calldata _call
  ) internal pure returns (bool) {
    if (_permission.target != _call.to) {
      return false;
    }

    bytes4 selector = bytes4(_call.data);

    // Handle different function calls
    if (selector == bytes4(keccak256("safeTransferFrom(address,address,uint256,uint256,bytes)"))) {
      (,, uint256 tokenId, uint256 amount,) = abi.decode(_call.data[4:], (address, address, uint256, uint256, bytes));
      return tokenId == _permission.tokenId && amount <= _permission.limit;
    } else if (selector == bytes4(keccak256("setApprovalForAll(address,bool)"))) {
      (, bool approved) = abi.decode(_call.data[4:], (address, bool));
      // Only allow revoking approval (setting to false)
      return !approved;
    }
    return false;
  }

  /// @notice Validates a remote permission by calling external validator
  function validateRemote(
    RemotePermission memory _permission,
    Payload.Call calldata _call
  ) internal view returns (bool) {
    return IPermissionValidator(_permission.validator).validatePermission(_permission.data, _call);
  }

  /// @notice Validates a rules permission
  function validateRules(RulesPermission memory _permission, Payload.Call calldata _call) internal pure returns (bool) {
    if (_permission.target != _call.to) {
      return false;
    }

    // Check each rule
    for (uint256 i = 0; i < _permission.rules.length; i++) {
      ParameterRule memory rule = _permission.rules[i];

      // Ensure call data is long enough
      if (_call.data.length < rule.offset + 32) {
        return false;
      }

      // Extract value from calldata at offset
      bytes32 value = _call.data.readBytes32(rule.offset);

      // Apply mask
      value = value & rule.mask;

      // Compare based on operation
      if (rule.operation == ParameterRuleOperation.EQUAL) {
        if (value != rule.value) {
          return false;
        }
      } else if (rule.operation == ParameterRuleOperation.NOT_EQUAL) {
        if (value == rule.value) {
          return false;
        }
      } else if (rule.operation == ParameterRuleOperation.GREATER_THAN_OR_EQUAL) {
        if (uint256(value) < uint256(rule.value)) {
          return false;
        }
      } else if (rule.operation == ParameterRuleOperation.LESS_THAN_OR_EQUAL) {
        if (uint256(value) > uint256(rule.value)) {
          return false;
        }
      }
    }

    return true;
  }

  /// @notice Gets the usage limit from a permission
  /// @param permission The encoded permission to extract the limit from
  /// @return uint256 The usage limit value (0 if no limit)
  function getLimit(
    EncodedPermission memory permission
  ) internal pure returns (uint256) {
    if (permission.pType == PermissionType.ERC20) {
      ERC20Permission memory ep = abi.decode(permission.data, (ERC20Permission));
      return ep.limit;
    } else if (permission.pType == PermissionType.ERC1155) {
      ERC1155Permission memory ep = abi.decode(permission.data, (ERC1155Permission));
      return ep.limit;
    } else if (permission.pType == PermissionType.NATIVE) {
      NativeTransferPermission memory np = abi.decode(permission.data, (NativeTransferPermission));
      return np.limit;
    }
    return 0;
  }

  /// @notice Extracts the usage amount from a permission and call data
  /// @param permission The encoded permission containing the type
  /// @param call The call data to extract the amount from
  /// @return uint256 The usage amount (0 if no limit applies)
  function getUsageAmount(
    EncodedPermission memory permission,
    Payload.Call calldata call
  ) internal pure returns (uint256) {
    if (permission.pType == PermissionType.ERC20) {
      bytes4 selector = bytes4(call.data);
      if (
        selector == bytes4(keccak256("transfer(address,uint256)"))
          || selector == bytes4(keccak256("approve(address,uint256)"))
      ) {
        (, uint256 amount) = abi.decode(call.data[4:], (address, uint256));
        return amount;
      } else if (selector == bytes4(keccak256("transferFrom(address,address,uint256)"))) {
        (,, uint256 amount) = abi.decode(call.data[4:], (address, address, uint256));
        return amount;
      }
    } else if (permission.pType == PermissionType.ERC1155) {
      bytes4 selector = bytes4(call.data);
      if (selector == bytes4(keccak256("safeTransferFrom(address,address,uint256,uint256,bytes)"))) {
        (,,, uint256 amount,) = abi.decode(call.data[4:], (address, address, uint256, uint256, bytes));
        return amount;
      }
    } else if (permission.pType == PermissionType.NATIVE) {
      return call.value;
    }
    return 0;
  }

  /// @notice Extracts the usage amount directly from call data based on function selector
  /// @param call The call data to extract the amount from
  /// @return uint256 The usage amount (0 if no amount found)
  function getUsageAmountFromCall(
    Payload.Call calldata call
  ) internal pure returns (uint256) {
    bytes4 selector = bytes4(call.data);

    // ERC20 transfer/transferFrom/approve
    if (
      selector == bytes4(keccak256("transfer(address,uint256)"))
        || selector == bytes4(keccak256("approve(address,uint256)"))
    ) {
      (, uint256 amount) = abi.decode(call.data[4:], (address, uint256));
      return amount;
    } else if (selector == bytes4(keccak256("transferFrom(address,address,uint256)"))) {
      (,, uint256 amount) = abi.decode(call.data[4:], (address, address, uint256));
      return amount;
    }
    // ERC1155 safeTransferFrom
    else if (selector == bytes4(keccak256("safeTransferFrom(address,address,uint256,uint256,bytes)"))) {
      (,,, uint256 amount,) = abi.decode(call.data[4:], (address, address, uint256, uint256, bytes));
      return amount;
    }
    // Native transfer (no selector needed)
    else if (call.value > 0) {
      return call.value;
    }

    return 0;
  }

}
