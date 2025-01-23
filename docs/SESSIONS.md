# **Technical Document: Sequence Session Management**

This document describes how Sequence sessions work, focusing on the permission system and validation modes (implicit vs explicit). It explains the core concepts, permission types, and validation logic.

---

## **1. Overview**

Sequence sessions provide a flexible way to delegate specific permissions to session signers. The system supports two distinct validation modes, controlled by the **Session Manager**.

- **Implicit Mode**: Simplified validation using contract-level approval and user defined blacklists
- **Explicit Mode**: Detailed permission-based validation with configurable limits

---

## **2. Session Manager**

The **Session Manager** is Sapient Signer for the wallet. In the default configuration, this signer has infinite weight and any payload is accepted provided the validations pass.

The Session Manager uses the provided attestation signature to derive a **Global Signer**. This, the explicit session configurations, and the implicit session blacklist are used to generate an image hash for the configuration. The image hash is rolled up to the wallet and validated as part of the derived image hash of the wallet. To use an updated image hash, the wallet's configuration must also be updated.

---

## **3. Implicit Mode**

Upon login, the client will generate a session key and provide additional context to the wallet. The wallet will then approve the session and attest to the data provided.

Permissions to access functions defined under this approach are automatically granted to the session signer. This way, a session signer can non-interactively sign and transmit payloads without calling the wallet. Permissions outside this mode must be granted with explicit approval.

To enable implicit permissions, an application's contract must implement the `ISignalsImplicitMode` interface.

```solidity
interface ISignalsImplicitMode {
    function acceptImplicitRequest(
        address _wallet,
        Attestation calldata _attestation,
        bytes32 _redirectUrlHash,
        Payload.Call calldata _call
    ) external view returns (bytes32);
}
```

This function is called by the Session Manager when a payload is received. The contract must validate the attestation and the call to ensure it is valid for the scope of the session.

At a minimum, it is expected that the application will validate the `_redirectUrlHash` to ensure the request is coming from a trusted source. Particular functions and parameters may be validated by checking the `_call` content.

The application may also validate additional data provided in the `_attestation`. This may be app data, such as offchain state.

The configuration includes a blacklist of addresses that are not allowed to be called in implicit mode. This is used to prevent the session signer from calling any of these addresses.

Calls made via implicit mode are not allowed to transfer value.

---

## **4. Explicit Mode**

Explicit mode provides granular control through specific permissions. These permissions are encoded into the session configuration. In order to use this mode, the wallet must sign a transaction to update the configuration of the wallet to include the sessions with the given permissions. This is done interactively and requires the wallet to be unlocked.

Each session signer has a set of encoded permissions as defined below. Each call in the payload is validated against the permissions of the session signer. The session signer also has an optional deadline outside of which the call is not valid.

//TODO Payload level permissions

Permissions with limits are validated against the actual usage of the call. Additionally, the session signer has an optional value limit. When using these limits, the session manager ensure the payload includes a call to `incrementUsage` to update the usage counters for each permission that is used.

## **4.1. Permission Types**

The system defines several permission types through the `Permissions` library:

```solidity
enum PermissionType {
    FUNCTION_CALL,   // Basic function calls
    NATIVE,          // Native token transfers
    ERC20,           // ERC20 token operations
    ERC721,          // NFT operations
    ERC1155,         // Multi-token operations
    RULES,           // Calldata rules based permissions
    REMOTE           // Extended permission types
}
```

Each permission type has its own structure and validation rules.

### **4.1.1. Function Call**

A function call permission is a simple call to a target contract with a specific function selector.

### **4.1.2. Native Token Transfer**

A native token transfer permission is a simple call to transfer native tokens to a target address. This permission does not allow calldata to be included in the call.

### **4.1.3. ERC20 Token Operations**

An ERC20 token operation permission is a call to an ERC20 contract's `transfer`, `transferFrom` and `approve` functions.

The usage of these functions is tracked by the `limitUsage` mapping.

### **4.1.4. ERC721 Token Operations**

An ERC721 token operation permission is a call to an ERC721 contract's `transferFrom`, `safeTransferFrom`, `safeTransferFrom` and `approve` functions.

The usage of these functions is tracked by the `limitUsage` mapping.

### **4.1.5. ERC1155 Token Operations**

An ERC1155 token operation permission is a call to an ERC1155 contract's `transferFrom`, `safeTransferFrom`, `safeTransferFrom` and `approve` functions.

The usage of these functions is tracked by the `limitUsage` mapping.

### **4.1.6. Calldata Rules Permission**

The calldata rules permission is a set of rules that must be met for a call to be valid. Each rule is validates as follows:

1. Retrieve a `bytes32` value from the calldata at the specified `offset`.
2. Apply the `mask` to the value.
3. Compare the value to the `value` using the `operation` defined in the rule.

The operations are defined as follows:

```solidity
enum ParameterRuleOperation {
    EQUAL,
    NOT_EQUAL,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN_OR_EQUAL
}
```

Using a calldata offset and mask enables any element within the calldata to be validated. This includes things like function selectors, array lengths and tightly packed values.

### **4.1.7. Remote Permission**

Remote permissions are used to offer extendability to the system. An integrator may define a new permission type and implement the `IPermissionValidator` interface to add it to the system. Calls using this permission type will be validated by the associated `IPermissionValidator` implementation.

## **4.2. Limit Usage Tracking**

The system tracks usage through:

1. **Usage hash generation**:

   ```solidity
   function getUsageHash(
       address wallet,
       address sessionAddress,
       address targetAddress
   ) public pure returns (bytes32)
   ```

   A hash of the wallet, session signer and target address is used to track usage of each permission.
   Rotating the session signer resulted in a refreshed limit usage.

2. **Per target counters**:

   ```solidity
   mapping(bytes32 => uint256) private limitUsage;
   ```

   The `limitUsage` mapping is compared against the usage amount in the payload and the limit approved by the associated permission.

3. **Limit updates**:
   ```solidity
   function incrementLimitUsage(bytes32[] calldata limitUsageHashes, uint256[] calldata usageAmounts) external;
   ```
   The session manager checks that the wallet has called `incrementUsage` with the correct values for each permission that is used.

---

## **5. Security Considerations**

In all cases, the **Session Manager** will block uses of delegate calls.

---

## **6. Signature Format**

//TODO
