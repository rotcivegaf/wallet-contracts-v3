// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import { Vm } from "forge-std/Test.sol";

using PrimitivesCli for Vm;

library PrimitivesCli {

  function root(
    Vm _vm
  ) internal view returns (string memory) {
    return _vm.envString("SEQ_SDK_CMD");
  }

  function shffi(Vm _vm, string memory _command) internal returns (bytes memory) {
    string[] memory args = new string[](3);
    args[0] = "sh";
    args[1] = "-c";
    args[2] = _command;
    return _vm.ffi(args);
  }

  function randomBytes(Vm _vm, uint256 _length) internal returns (bytes memory) {
    string memory command =
      string(abi.encodePacked("head -c ", _vm.toString(_length), " /dev/urandom | xxd -p -c ", _vm.toString(_length)));
    return _vm.shffi(command);
  }

  function toPackedPayload(Vm _vm, Payload.Decoded memory _decoded) internal returns (bytes memory) {
    string memory randomId = _vm.toString(randomBytes(_vm, 8));
    string memory path = string(abi.encodePacked("/tmp/seq-td-", randomId));
    _vm.writeFile(path, _vm.toString(abi.encode(_decoded)));

    string memory command = string(abi.encodePacked("cat ", path, " | ", _vm.root(), " payload to-packed"));

    bytes memory result = _vm.shffi(command);
    _vm.removeFile(path);
    return result;
  }

  function newConfig(
    Vm _vm,
    uint16 _threshold,
    uint256 _checkpoint,
    string memory _elements
  ) internal returns (string memory) {
    string memory command = string(
      abi.encodePacked(
        _vm.root(),
        " config new --threshold ",
        _vm.toString(_threshold),
        " --checkpoint ",
        _vm.toString(_checkpoint),
        " '",
        _elements,
        "'"
      )
    );
    return string(_vm.shffi(command));
  }

  function toEncodedConfig(Vm _vm, string memory _config) internal returns (bytes memory) {
    string memory command = string(abi.encodePacked(_vm.root(), " config encode '", _config, "'"));
    return _vm.shffi(command);
  }

  function toEncodedSignature(Vm _vm, string memory _config, string memory _elements) internal returns (bytes memory) {
    string memory command = string(abi.encodePacked(_vm.root(), " signature encode '", _config, "' ", _elements));
    return _vm.shffi(command);
  }

  function toPackedPermission(Vm _vm, string memory _permission) internal returns (bytes memory) {
    string memory command = string(abi.encodePacked(_vm.root(), " permission to-packed '", _permission, "'"));
    return _vm.shffi(command);
  }

  function toPackedSessionPermission(Vm _vm, string memory _sessionPermission) internal returns (bytes memory) {
    string memory command =
      string(abi.encodePacked(_vm.root(), " permission to-packed-session '", _sessionPermission, "'"));
    return _vm.shffi(command);
  }

  function getImageHash(Vm _vm, string memory _config) internal returns (bytes32) {
    string memory command = string(abi.encodePacked(_vm.root(), " config image-hash '", _config, "'"));
    return bytes32(_vm.shffi(command));
  }

  function randomConfig(Vm _vm, uint256 _maxDepth, uint256 _seed) internal returns (string memory) {
    string memory command = string(
      abi.encodePacked(
        root(_vm),
        " dev-tools random-config --max-depth ",
        _vm.toString(_maxDepth),
        " --min-threshold-on-nested 1 --seed ",
        _vm.toString(_seed)
      )
    );
    return string(_vm.shffi(command));
  }

  function randomSessionTopology(Vm _vm, uint256 _maxDepth, uint256 _seed) internal returns (string memory) {
    string memory command = string(
      abi.encodePacked(
        root(_vm),
        " dev-tools random-session-topology --max-depth ",
        _vm.toString(_maxDepth),
        " --max-permissions 1 --max-rules 1 --seed ",
        _vm.toString(_seed)
      )
    );
    return string(_vm.shffi(command));
  }

  function concatSignatures(Vm _vm, bytes[] memory _signatures) internal returns (bytes memory) {
    string memory command = string(abi.encodePacked(_vm.root(), " signature concat"));
    for (uint256 i = 0; i < _signatures.length; i++) {
      command = string(abi.encodePacked(command, " ", _vm.toString(_signatures[i])));
    }
    return _vm.shffi(command);
  }

  // Session explicit

  function emptyExplicitSession(
    Vm _vm
  ) internal returns (string memory) {
    string memory command = string(abi.encodePacked(_vm.root(), " session explicit empty"));
    return string(_vm.shffi(command));
  }

  function addExplicitSession(
    Vm _vm,
    string memory _session,
    string memory _sessionConfig
  ) internal returns (string memory) {
    string memory command =
      string(abi.encodePacked(_vm.root(), " session explicit add '", _session, "' '", _sessionConfig, "'"));
    return string(_vm.shffi(command));
  }

  function removeExplicitSession(
    Vm _vm,
    address _sessionAddr,
    string memory _sessionConfig
  ) internal returns (string memory) {
    string memory command = string(
      abi.encodePacked(_vm.root(), " session explicit remove '", _vm.toString(_sessionAddr), "' '", _sessionConfig, "'")
    );
    return string(_vm.shffi(command));
  }

  function useSessionExplicit(
    Vm _vm,
    string memory _sessionSignature,
    uint8[] memory _permissionIdxPerCall,
    string memory _sessionTopology
  ) internal returns (bytes memory) {
    string memory permissionIdxPerCall = "";
    for (uint256 i = 0; i < _permissionIdxPerCall.length; i++) {
      permissionIdxPerCall =
        string(abi.encodePacked(permissionIdxPerCall, i > 0 ? "," : "", _vm.toString(_permissionIdxPerCall[i])));
    }
    string memory command = string(
      abi.encodePacked(
        _vm.root(),
        " session explicit use '",
        _sessionSignature,
        "' '",
        permissionIdxPerCall,
        "' '",
        _sessionTopology,
        "' "
      )
    );
    return _vm.shffi(command);
  }

  function toPackedSessionTopology(Vm _vm, string memory _sessionTopology) internal returns (bytes memory) {
    string memory command =
      string(abi.encodePacked(_vm.root(), " session explicit to-packed-topology '", _sessionTopology, "'"));
    return _vm.shffi(command);
  }

}
