


export type Call = {
  to: `0x${string}`
  value: bigint
  data: Uint8Array
  gasLimit: bigint
  delegateCall: boolean
  onlyFallback: boolean
  behaviorOnError: 'ignore' | 'revert' | 'abort'
}

export type CallPayload = {
  type: 'call'
  nonce: bigint
  calls: Call[]
}

export type MessagePayload = {
  type: 'message'
  message: Uint8Array
}

export type ConfigUpdatePayload = {
  type: 'config-update'
  imageHash: `0x${string}`
}

export type DigestPayload = {
  type: 'digest'
  digest: `0x${string}`
}

export type ParentPayload = {
  parentWallets?: `0x${string}`[]
}

export type Payload = (
  CallPayload | MessagePayload | ConfigUpdatePayload | DigestPayload
)

export type ParentedPayload = Payload & ParentPayload

export function fromMessage(message: Uint8Array): Payload {
  return {
    type: 'message',
    message
  }
}

export function fromConfigUpdate(imageHash: `0x${string}`): Payload {
  return {
    type: 'config-update',
    imageHash
  }
}

export function fromDigest(digest: `0x${string}`): Payload {
  return {
    type: 'digest',
    digest
  }
}

export function fromCall(nonce: bigint, calls: Call[]): Payload {
  return {
    type: 'call',
    nonce,
    calls
  }
}

function encodeCalls(calls: Call[]): Uint8Array {
  
}
