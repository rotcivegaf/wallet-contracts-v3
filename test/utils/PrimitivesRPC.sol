// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import { Payload } from "../../src/modules/Payload.sol";
import { Vm } from "forge-std/Test.sol";

/// This library replicates the same usage as your old PrimitivesCli, but via
/// Foundry's `vm.rpc` JSON-RPC calls instead of `ffi`.
/// This is done for performance reasons, as `ffi` is very slow.
library PrimitivesRPC {

  uint256 private constant COUNTER_UNINITIALIZED = 0;
  uint256 private constant COUNTER_SLOT = uint256(keccak256("sequence.primitives-rpc.counter"));

  function getCounter() private view returns (uint256) {
    bytes32 counterSlot = bytes32(COUNTER_SLOT);
    uint256 value;
    assembly {
      value := sload(counterSlot)
    }
    return value;
  }

  function setCounter(
    uint256 value
  ) private {
    bytes32 counterSlot = bytes32(COUNTER_SLOT);
    assembly {
      sstore(counterSlot, value)
    }
  }

  function rpcURL(
    Vm _vm
  ) internal returns (string memory) {
    uint256 minPort = uint256(_vm.envUint("SEQ_SDK_RPC_MIN_PORT"));
    uint256 maxPort = uint256(_vm.envUint("SEQ_SDK_RPC_MAX_PORT"));
    require(maxPort >= minPort, "Invalid port range");

    // Get or initialize counter
    uint256 counter = getCounter();
    if (counter == COUNTER_UNINITIALIZED) {
      counter = uint256(keccak256(abi.encodePacked(msg.data)));
    }

    // Increment counter
    counter++;
    setCounter(counter);

    // Generate port within range using counter
    uint256 range = maxPort - minPort + 1;
    uint256 randomPort = minPort + (counter % range);

    string memory prefix = _vm.envString("SEQ_SDK_RPC_URL_PREFIX");
    string memory suffix = _vm.envString("SEQ_SDK_RPC_URL_SUFFIX");

    return string.concat(prefix, _vm.toString(randomPort), suffix);
  }

  // ----------------------------------------------------------------
  // devTools
  // ----------------------------------------------------------------

  function randomConfig(
    Vm _vm,
    uint256 _maxDepth,
    uint256 _seed,
    uint256 _minThresholdOnNested,
    string memory _checkpointer
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"maxDepth":',
      _vm.toString(_maxDepth),
      ',"seed":"',
      _vm.toString(_seed),
      '","minThresholdOnNested":',
      _vm.toString(_minThresholdOnNested),
      ',"checkpointer":"',
      _checkpointer,
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "devTools_randomConfig", params);
    return string(rawResponse);
  }

  function randomSessionTopology(
    Vm _vm,
    uint256 _maxDepth,
    uint256 _maxPermissions,
    uint256 _maxRules,
    uint256 _seed
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"maxDepth":',
      _vm.toString(_maxDepth),
      ',"maxPermissions":',
      _vm.toString(_maxPermissions),
      ',"maxRules":',
      _vm.toString(_maxRules),
      ',"seed":"',
      _vm.toString(_seed),
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "devTools_randomSessionTopology", params);
    return string(rawResponse);
  }

  // ----------------------------------------------------------------
  // payload
  // ----------------------------------------------------------------

  function toPackedPayload(Vm _vm, Payload.Decoded memory _decoded) internal returns (bytes memory) {
    string memory params = string.concat('{"payload":"', _vm.toString(abi.encode(_decoded)), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "payload_toPacked", params);
    return (rawResponse);
  }

  // ----------------------------------------------------------------
  // config
  // ----------------------------------------------------------------

  function newConfig(
    Vm _vm,
    uint16 _threshold,
    uint256 _checkpoint,
    string memory _elements
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"threshold":"',
      _vm.toString(_threshold),
      '","checkpoint":"',
      _vm.toString(_checkpoint),
      '","from":"flat","content":"',
      _elements,
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_new", params);
    return string(rawResponse);
  }

  function toEncodedConfig(Vm _vm, string memory configJson) internal returns (bytes memory) {
    string memory params = string.concat('{"input":', configJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_encode", params);
    return (rawResponse);
  }

  function getImageHash(Vm _vm, string memory configJson) internal returns (bytes32) {
    string memory params = string.concat('{"input":', configJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_imageHash", params);
    bytes memory hexBytes = (rawResponse);
    return abi.decode(hexBytes, (bytes32));
  }

  // ----------------------------------------------------------------
  // signature
  // ----------------------------------------------------------------

  function toEncodedSignature(
    Vm _vm,
    string memory configJson,
    string memory signatures,
    bool _chainId
  ) internal returns (bytes memory) {
    // If you wanted no chainId, adapt the JSON, e.g. `"chainId":false`.
    string memory params = string.concat(
      '{"input":', configJson, ',"signatures":"', signatures, '","chainId":', _chainId ? "true" : "false", "}"
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "signature_encode", params);
    return (rawResponse);
  }

  function concatSignatures(Vm _vm, bytes[] memory _signatures) internal returns (bytes memory) {
    string memory arrayPrefix = '{"signatures":[';
    string memory arraySuffix = "]}";
    string memory arrayMid;
    for (uint256 i = 0; i < _signatures.length; i++) {
      arrayMid = string.concat(arrayMid, i == 0 ? '"' : ',"', _vm.toString(_signatures[i]), '"');
    }
    string memory params = string.concat(arrayPrefix, arrayMid, arraySuffix);
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "signature_concat", params);
    return (rawResponse);
  }

  // ----------------------------------------------------------------
  // permission
  // ----------------------------------------------------------------

  function toPackedPermission(Vm _vm, string memory permissionJson) internal returns (bytes memory) {
    string memory params = string.concat('{"permission":', permissionJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "permission_toPacked", params);
    return (rawResponse);
  }

  function toPackedSessionPermission(Vm _vm, string memory sessionJson) internal returns (bytes memory) {
    string memory params = string.concat('{"sessionPermission":', sessionJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "permission_toPackedSession", params);
    return (rawResponse);
  }

  // ----------------------------------------------------------------
  // session explicit
  // ----------------------------------------------------------------

  function emptyExplicitSession(
    Vm _vm
  ) internal returns (string memory) {
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_empty", "{}");
    return string(rawResponse);
  }

  function addExplicitSession(
    Vm _vm,
    string memory sessionInput,
    string memory topologyInput
  ) internal returns (string memory) {
    string memory params = string.concat('{"explicitSession":', sessionInput, ',"sessionTopology":', topologyInput, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_add", params);
    return string(rawResponse);
  }

  function removeExplicitSession(
    Vm _vm,
    address explicitSessionAddress,
    string memory topologyInput
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"explicitSessionAddress":"', _vm.toString(explicitSessionAddress), '","sessionTopology":', topologyInput, "}"
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_remove", params);
    return string(rawResponse);
  }

  function useSessionExplicit(
    Vm _vm,
    string memory signatureInput,
    uint8[] memory _permissionIdxPerCall,
    string memory topologyInput
  ) internal returns (bytes memory) {
    string memory permissionIdxPerCall = "";
    for (uint256 i = 0; i < _permissionIdxPerCall.length; i++) {
      permissionIdxPerCall =
        string(abi.encodePacked(permissionIdxPerCall, i > 0 ? "," : "", _vm.toString(_permissionIdxPerCall[i])));
    }

    string memory params = string.concat(
      '{"signature":"',
      signatureInput,
      '","permissionIndexes":"',
      permissionIdxPerCall,
      '","sessionTopology":',
      topologyInput,
      "}"
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_use", params);
    return (rawResponse);
  }

  function toPackedSessionTopology(Vm _vm, string memory topologyInput) internal returns (bytes memory) {
    string memory params = string.concat('{"sessionTopology":', topologyInput, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_toPackedTopology", params);
    return (rawResponse);
  }

}
