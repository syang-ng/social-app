import {type BskyAgent} from '@atproto/api'

export function notifyPromotionServiceForSavedFeeds({
  agent: _agent,
  savedFeeds: _savedFeeds,
}: {
  agent: BskyAgent
  savedFeeds: Array<{type: string; value: string}>
}): Promise<void> {
  return Promise.resolve()
}

export type EncryptedReceiptResponse = {
  taskId: string
  spenderDid: string
  receipt: string
  createdAt?: string
  reused?: boolean
}

export function requestEncryptedReceipt(_args: {
  serviceUrl: string
  taskId: string
  spenderDid: string
  accessJwt?: string
}): Promise<EncryptedReceiptResponse> {
  return Promise.reject(
    new Error('requestEncryptedReceipt is only implemented on web'),
  )
}

export function spendEncryptedReceipt(_args: {
  serviceUrl: string
  taskId: string
  spenderDid: string
  receipt: string | Record<string, unknown>
  accessJwt?: string
}): Promise<{
  taskId: string
  spenderDid: string
  r: string
  spentAt: string
  duplicate: boolean
}> {
  return Promise.reject(
    new Error('spendEncryptedReceipt is only implemented on web'),
  )
}

export function autoSpendPromotionReceipt(_args: {
  serviceUrl: string
  taskId: string
  spenderDid: string
  accessJwt?: string
}): Promise<{spent: boolean; reason?: string}> {
  return Promise.resolve({
    spent: false,
    reason: 'autoSpendPromotionReceipt is only implemented on web',
  })
}
