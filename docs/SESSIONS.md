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

Each session signer has a set of encoded permissions defined by rules. Each call in the payload is validated against the permissions of the session signer. The session signer also has an optional deadline outside of which the call is not valid.

## **4.1. Rules-Based Permissions**

The permission system uses a flexible rules-based approach where each permission consists of:

1. A target contract address
2. An array of parameter rules that validate the calldata

Each parameter rule validates as follows:

1. Retrieve a `bytes32` value from the calldata at the specified `offset`
2. Apply the `mask` to the value
3. Compare the value to the `value` using the specified `operation`
4. Optionally track cumulative usage for the rule

The operations available for comparison are:

```solidity
enum ParameterOperation {
    EQUAL,
    NOT_EQUAL,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN_OR_EQUAL
}
```

Using a calldata offset and mask enables validation of any element within the calldata. This includes:

- Function selectors
- Parameter values
- Array lengths
- Tightly packed values
- Token amounts
- Token IDs

### **4.1.1 Cumulative Usage Tracking**

Rules can be marked as cumulative to track usage of a specific parameter across multiple calls. For these rules:

1. The current value is added to previous usage
2. The total is compared against the rule's value limit
3. Usage is tracked per wallet-session-permission combination

When a transaction includes any cumulative rules, it **must** include a call to `incrementUsageLimit` as the last operation in the payload. This requirement ensures atomic updates to usage tracking. Specifically:

1. The last call in the payload must be to the SessionManager contract
2. It must call the `incrementUsageLimit` function
3. The call must use `BEHAVIOR_REVERT_ON_ERROR`
4. The call must include all usage limits from the transaction

For example, if a transaction includes transfers that use cumulative rules, the payload would look like:

```solidity
calls = [
    // Transfer operations
    transferCall1,
    transferCall2,
    // Required final call
    {
        to: sessionManager,
        data: incrementUsageLimit(usageLimits),
        behaviorOnError: BEHAVIOR_REVERT_ON_ERROR
    }
]
```

If this call is missing or incorrect, the transaction will revert.

---

## **5. Security Considerations**

In all cases, the **Session Manager** will block uses of delegate calls.

---

## **6. Signature Format**

The session signature is encoded as a compact byte array containing all necessary components for validation. The components are encoded sequentially as follows:

### **6.1 Basic Structure**

1. Session Signature (64 bytes) - Compact ERC-2098 format

   - r (32 bytes): Signature component
   - sv (32 bytes): Combined s-value and v-parity bit

2. Attestation (variable length)

   - approvedSigner (20 bytes): Address of the approved signer
   - identityType (4 bytes): Type of identity
   - issuerHash (32 bytes): Hash of the issuer
   - audienceHash (32 bytes): Hash of the audience
   - authData (variable):
     - length (3 bytes): Length of auth data
     - data (variable): Authentication data
   - applicationData (variable):
     - length (3 bytes): Length of application data
     - data (variable): Application-specific data

3. Global Signer Signature (64 bytes) - Compact ERC-2098 format

   - r (32 bytes): Signature component
   - sv (32 bytes): Combined s-value and v-parity bit

4. Encoded Permissions Tree

   - length (3 bytes): Length of encoded permissions data
   - data (variable): Encoded permissions tree containing:
     - Flag (4 bits): Indicates node type (0=Permissions, 1=Node, 2=Branch)
     - Extra (4 bits): Reserved for future use
     - Node-specific data (variable)

5. Implicit Blacklist

   - length (3 bytes): Number of blacklisted addresses
   - addresses (20 bytes each): Array of blacklisted addresses

6. Permission Indices
   - length (3 bytes): Number of permission indices
   - indices (1 byte each): Array of permission indices per call

### **6.2 Example**

```
[Session Sig (r,sv)][Attestation][Global Sig (r,sv)][Permissions len][Permissions data][Blacklist len][Blacklist addrs][Indices len][Indices]
```

### **6.3 Decoding**

The signature is decoded sequentially using pointer arithmetic, advancing the pointer after reading each component. This format allows for efficient reading of components without requiring ABI decoding.

The decoded components are used to:

1. Recover the session signer from the payload signature and verify it matches the attestation's approved signer
2. Verify the global signer's attestation using the attestation hash
3. Recover the permissions tree and find the signer's permissions
4. Set implicit mode if no permissions are found

### **6.4 Permissions Tree Structure**

The permissions tree is encoded as a series of nodes, each starting with a flag byte:

- **Permissions Node (0x0-)**: Contains signer address, value limit, deadline, and permissions array
- **Hash Node (0x1-)**: Contains a pre-computed hash
- **Branch Node (0x2-)**: Contains a nested permissions tree

Each node contributes to the final permissions root through sequential hashing.
