# Sequence chained signatures

This document provides an overview of the rationale behind the “chained” signatures of the Sequence wallet contracts.

## **1. Overview**

Sequence uses chained signatures as a mechanism to perform “configuration updates”, in such a way that configuration updates are both: 1. Valid on all networks 2. Zero cost until utilized

In this way, “chained signatures” transform the representation of a configuration in Sequence v3 from a simple static element to a state channel.

A configuration can sign a “configuration update”, which acts as an authorization to another configuration to fully act on behalf of the wallet. These authorized configurations can in turn perform additional authorizations, forming a chain of N configurations.

Configurations are strictly ordered by their “checkpoint”. A configuration cannot “delegate” into a configuration with a checkpoint that is below or equal to the current configuration. This ensures that no old sections of the state channel can be resurfaced.

```
Wallet lifecycle
───────────────────────────────────────────────────────────────▷
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌─────────┐
│ Config 1 ├──┬──▶│ Config 2 ├──┬──▶│ Config 3 ├──┬──▶│ Payload │
└──────────┘  │   └──────────┘  │   └──────────┘  │   └─────────┘
          Authorize         Authorize           Sign
```

## **2. Format**

Chained signatures are encoded as a list of signatures, in reverse order. This is done to allow for the contract to recover from the payload to the configuration that is currently defined by the contract. Intermediary configurations are not directly encoded, but rather recovered from the previous signature, until the last configuration which is recovered and validated against the contract’s current configuration.

All chained signatures start by setting the global signature flag to `XXXX XXX1` (`flag & 0x01`), only the first bit is read, every other bit is ignored.

Afterwards, each signature part is encoded, prefixed by 3 bytes that determine their size.

```
 ┌───▶ Global flag for chained     ┌─▶ Intermediary
 │     XXXX XXX1                   │   signature
 │     Signals we are reading      │   repeats N times
 │     a chained signature         │
 │                                 │
 ○                      ───────────┴────────
01 0001ff 5151515151... 000803 5252525252... 00cb55 5353535353...
   ──┬─── ──┬──────────  Size    Signature   ──┬─────────────────
     │      │                                  │
     │      │   Dynamic length                 │   Final signature
     │      │   first signature                │   should recover
     │      └─▶ (for Payload)                  └─▶ to configuration
     │                                             defined by contract
     │    3 bytes:
     └──▶ Next signature
          part size
```

## **2. Rules**

Chained signatures MUST comply with the following rules to be considered valid.

### Weight > Threshold

All signature parts must meet their respective thresholds.

### Payload order

1. The first signature recovers the given Payload. If its threshold is met, then it generates an `imageHash` which corresponds to the root of a Merkle tree that defines the configuration of the wallet.

2. Following signatures recover the `imageHash` of the previous signature, bundled within a payload of the `KIND_CONFIG_UPDATE` kind. They, in turn, recover to their own next `imageHash`.

3. After the last signature has been recovered, the resulting `imageHash` must match the one defined by the contract.

```
┌──────────────┐        ┌─────────────────────┐        ┌─────────────────────┐
│Main payload  │        │Config update payload│        │Config update payload│
│(e.g. send tx)│        │ImageHash 1          │        │ImageHash 2          │
└─────────────┬┘        └─▲──────────────────┬┘        └─▲──────────────────┬┘
              │           │                  │           │                  │
    Recover ──┤           │        Recover ──┤           │        Recover ──┤
              │           │                  │           │                  │
   ┌──────────▼┐ Generate │       ┌──────────▼┐ Generate │       ┌──────────▼┐
   │ImageHash 1├──────────┘       │ImageHash 2├──────────┘       │ImageHash 3│
   └───────────┘                  └───────────┘                  └─────┬─────┘
                                                                       │
                                                                       │
                                                                       │
                                                                 ╔═════▼═════╗
                                                                 ║ Is valid? ║
                                                                 ╚═══════════╝
```

### Checkpoint

Each wallet configuration defines a checkpoint, checkpoints define a strict order in which these configurations can be used **in the context of a chained signature**, this acts as a form of replay protection that blocks the usage of a previous section of the state channel **in case the state channel ever repeats configurations**.

For example, a wallet has a configuration with signers `A & B`, then it is updated to `A, B & C` and then updated back again to `A & B`. Afterwards, another update is queued, this time to `A, B & D`. Without the checkpoints, a malicious actor (C) may exploit the first update (where `C` was added) even if the wallet already evicted `C` as a signer.

```
                      Checkpoint 2 -> 0 forbidden
              ┌─────────────────────────────────────────────┐
              │                                             │
              x                                             │
┌───────────────┐     ┌─────────────────┐     ┌─────────────┴─┐     ┌─────────────────┐
│Signers: A & B │     │Signers: A, B & C│     │Signers: A & B │     │Signers: A, B & D│
│Checkpoint: 0  ├────▶│Checkpoint: 1    ├────▶│Checkpoint: 2  ├────▶│Checkpoint: 3    │
└───────────────┘     └─────────────────┘     └───────────────┘     └─────────────────┘
```

## **3. Checkpointer**

The checkpointer is an optional interface that helps wallets keep track of the latest valid configuration without publishing every intermediate step to all chains.

Because wallets exist on multiple chains, unused networks often lag behind and accumulate old states. The checkpointer solves this by announcing the last known valid configuration. Anything older is automatically considered invalid.

Wallet contracts don't specify how the checkpointer works internally. Its only job is to clearly state the latest valid configuration to prevent older states from being reused.

### Disabled checkpointer

Even when a checkpointer is defined by the configuration, the checkpointer has the capability to "disable" itself. This is useful for implementing escape hatches like timelocks or challenge periods, in case that the checkpointer becomes unresponsive or malicious. When the checkpointer announces a snapshot with `imageHash == bytes32(0)` it is considered disabled.

Notice that there is **no built in mechanism** to force the checkpointer to become disabled from within the wallet, any mechanism that may challenge and disable the checkpointer must be implemented on the checkpointer contract.

### Checkpointer data

When a checkpointer is defined by the configuration, obtaining the latest snapshot from it requires passing a generic `data` field to the checkpointer contract. This `data` field is provided within the signature, and it is entirely opaque to the wallet contract.

It wouldn't make sense for the checkpointer to be able to provide the snapshot directly from contract storage, as this would move the requirement of having to settle the state channel from the wallet contract to the checkpointer contract, instead, it is expected that the checkpointer will use the `data` field to validate a proof of the snapshot.

The proof may be implemented as a simple merkle proof, a signature from a trusted party or T.E.E., a zk proof from a keystore rollup, or any other mechanism that may allow the checkpointer to provide a valid snapshot.

### Checkpointer scenarios

Different scenarios exist depending on the current state of the wallet, state channel and checkpointer, and the relationship between them.

#### 1. Full sync

This happens when the wallet contract configuration is set to the latest configuration defined by the state channel, and the checkpointer reports the same configuration.

This scenario does not require the usage of chained signatures, as regular signatures are sufficient when the configuration that is being used matches the one defined by the contract.

```
  Checkpointer
 ┌───────────────────────────────────────────────┐
 │                        Wallet                 │
 │                       ┌─────────────────────┐ │
 │ ┌──────────────┐      │  ┌──────────────┐   │ │
 │ │ Config A & B ├──────┼──▶ Config A & C │   │ │
 │ └──────┬───────┘      │  └──────────────┘   │ │
 │        │              └─────────────────────┘ │
 └────────┼──────────────────────────────────────┘
          │
          ▼
Old state - Irrelevant
```

> Notice that even if no chained signatures are used, the checkpointer is still required to provide a valid snapshot of the latest configuration.

#### 2. Checkpointer Ahead, Wallet Behind

The state channel is ahead of the wallet contract, but the checkpointer knows about the latest configuration. In this scenario, the checkpointer provides a snapshot for the latest configuration, and the wallet **must** use a chained signature to sign the payload, using that latest configuration.

```
  Checkpointer
 ┌────────────────────────────────────────────────────────────────────┐
 │                        Wallet                                      │
 │                       ┌─────────────────────┐                      │
 │ ┌──────────────┐      │  ┌──────────────┐   │     ┌──────────────┐ │
 │ │ Config A & B ├──────┼──▶ Config A & C ├───┼─────▶ Config D & C │ │
 │ └──────┬───────┘      │  └──────────────┘   │     └───────┬──────┘ │
 │        │              └─────────────────────┘             │        │
 └────────┼──────────────────────────────────────────────────┼────────┘
          │                                                  │
          ▼                                                  ▼
Old state - Irrelevant                                  Latest state
```

#### 3. Checkpointer Behind, Wallet Synced

The checkpointer is behind the wallet contract, and there are no pending configurations in the state channel. In this scenario, the checkpointer will provide a snapshot with a checkpoint that is behind the wallet contract, and this will make the wallet contract ignore the checkpointer's snapshot.

This scenario may happen if the wallet is manually updated to a new configuration without notifying the checkpointer, or if the checkpointer hasn't had time to "react" and "catch up" with the wallet contract. It may be possible that the checkpointer is offline, and not reacting to any configuration changes.

```
  Checkpointer            Wallet
 ┌──────────────────┐    ┌─────────────────────┐
 │ ┌──────────────┐ │    │  ┌──────────────┐   │
 │ │ Config A & B ├─┼────┼──▶ Config A & C │   │
 │ └──────┬───────┘ │    │  └──────────────┘   │
 └────────┼─────────┘    └─────────────────────┘
          │
          │
          ▼
Old state - Irrelevant
```

#### 4. Wallet Behind, Checkpointer Further Behind

The checkpointer is behind the wallet contract, and there are pending configurations in the state channel. This scenario is very similar to the previous one, the only difference is that the wallet will use a chained signature to sign the payload, using the latest configuration.

Even if the wallet uses a chained signature, since the checkpointer's snapshot checkpoint is behind the wallet contract, the wallet will not use the checkpointer's snapshot.

```
  Checkpointer            Wallet
 ┌──────────────────┐    ┌─────────────────────┐
 │ ┌──────────────┐ │    │  ┌──────────────┐   │     ┌──────────────┐
 │ │ Config A & B ├─┼────┼──▶ Config A & C ├───┼─────▶ Config B & C │
 │ └──────┬───────┘ │    │  └──────────────┘   │     └──────┬───────┘
 └────────┼─────────┘    └─────────────────────┘            │
          │                                                 │
          │                                                 │
          ▼                                                 ▼
Old state - Irrelevant                                 Latest state
```

#### 5. Checkpointer Ahead, Wallet Behind, State Channel Further Ahead

The state channel has multiple configuration updates, the checkpointer is ahead of the wallet contract, yet the state channel goes further than the checkpointer. This scenario may happen if the latest configuration update happened recently and the checkpointer hasn't updated yet.

In this scenario, the checkpointer provides a snapshot, the wallet contract enforces a chained signature to sign the payload, forcing that the chained signature, at some point, goes over the checkpointer's snapshot.

```
  Checkpointer
 ┌────────────────────────────────────────────────────────────────────┐
 │                        Wallet                                      │
 │                       ┌─────────────────────┐                      │
 │ ┌──────────────┐      │  ┌──────────────┐   │     ┌──────────────┐ │       ┌──────────────┐
 │ │ Config A & B ├──────┼──▶ Config A & C ├───┼─────▶ Config D & C ├─┼───────▶ Config D & E │
 │ └──────┬───────┘      │  └──────────────┘   │     └──────────────┘ │       └──────┬───────┘
 │        │              └─────────────────────┘                      │              │
 └────────┼───────────────────────────────────────────────────────────┘              │
          │                                                                          │
          ▼                                                                          ▼
Old state - Irrelevant                                                          Latest state
```

#### 6. Wallet Synced, Checkpointer Dangling Ahead

The checkpointer may report a future configuration that is not part of the state channel. This may happen if the checkpointer is misbehaving, malicious, or there is a state channel update that has only been revealed to the checkpointer.

In this scenario, the checkpointer contract **must** provide with an escape hatch mechanism for either:

1. Provide the link to the dangling configuration
2. Disable itself

```
  Checkpointer
 ┌────────────────────────────────────────────────────────────────────┐
 │                        Wallet                                      │
 │                       ┌─────────────────────┐                      │
 │ ┌──────────────┐      │  ┌──────────────┐   │     ┌──────────────┐ │
 │ │ Config A & B ├──────┼──▶ Config A & C ├───┼─x   │ Config D & C │ │
 │ └──────┬───────┘      │  └───────┬──────┘   │     └───────┬──────┘ │
 │        │              └──────────┼──────────┘             │        │
 └────────┼─────────────────────────┼────────────────────────┼────────┘
          │                         │                        │
          ▼                         ▼                        ▼
Old state - Irrelevant         Latest state         Dangling, not linked
```
