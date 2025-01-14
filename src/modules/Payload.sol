// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;


library Payload {
  bytes32 private constant EIP712_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

  bytes32 private constant EIP712_DOMAIN_NAME_SEQUENCE =
    keccak256("Sequence Wallet");

  bytes32 private constant EIP712_DOMAIN_VERSION_SEQUENCE =
    keccak256("3");

  function domainSeparator(bool _noChainId) internal view returns (bytes32 _domainSeparator) {
    return keccak256(
      abi.encode(
        EIP712_DOMAIN_TYPEHASH,
        EIP712_DOMAIN_NAME_SEQUENCE,
        EIP712_DOMAIN_VERSION_SEQUENCE,
        _noChainId ? uint256(0) : uint256(block.chainid),
        address(this)
      )
    );
  }

  bytes32 private constant CALL_TYPEHASH =
    keccak256("Call(address to,uint256 value,bytes data,uint256 gasLimit,bool delegateCall,bool revertOnError)");

  bytes32 private constant CALLS_TYPEHASH =
    keccak256("Calls(Call[],address[] wallets)Call(address to,uint256 value,bytes data,uint256 gasLimit,bool delegateCall,bool revertOnError)");

  bytes32 private constant MESSAGE_TYPEHASH =
    keccak256("Message(bytes message,address[] wallets)");

  bytes32 private constant CONFIG_UPDATE_TYPEHASH =
    keccak256("ConfigUpdate(bytes32 imageHash)");

  bytes32 private constant DIGEST_TYPEHASH =
    keccak256("Digest(bytes32 digest)");

  uint8 internal constant KIND_TRANSACTIONS = 0x00;
  uint8 internal constant KIND_MESSAGE = 0x01;
  uint8 internal constant KIND_CONFIG_UPDATE = 0x02;
  uint8 internal constant KIND_DIGEST = 0x03;

  struct Call {
    address to;
    uint256 value;
    bytes data;
    uint256 gasLimit;
    bool delegateCall;
    bool revertOnError;
  }

  struct Decoded {
    uint8 kind;

    // Transaction kind
    Call[] calls;
    uint256 nonce;

    // Message kind
    // TODO: Maybe native 721 ?
    bytes message;
  
    // Config update kind
    bytes32 imageHash;

    // Digest kind for 1271
    bytes32 digest;

    // Parent wallets
    address[] parentWallets;
  }

  // Generate digest
  function subdigestFor(Payload.Decoded memory _decoded) internal pure returns (bytes32 _digest) {
    if (_decoded.kind == KIND_TRANSACTIONS) {
    }
  }

  // TODO: More efficient encoding/decoding
  function decode(bytes calldata _data) internal pure returns (Decoded memory _decoded) {
    _decoded = abi.decode(_data, (Decoded));
  }

  function encode(Decoded memory _decoded) internal pure returns (bytes memory _data) {
    _data = abi.encodePacked(_decoded.kind);
  }
}
