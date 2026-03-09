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

export type PromotionTask = {
  taskId: string
  postUri?: string
  feedUri?: string
  creatorDid?: string
  createdAt?: string
  [key: string]: unknown
}

export type PromotionPostViews = {
  postUri: string
  viewCount: number
  taskCount?: number
}

export type PromotionTaskAuditMaterial = {
  taskId: string
  bundleSeedBase64: string
  ppHashHex: string
  ppBinBase64: string
  verifierSecretKeyBase64: string
  savedAt?: string
}

export type PromotionTaskValidationState = {
  verifiedViewCount: number
  lastValidatedAt?: string
}

export type PromotionTaskValidationResult = {
  commitments: {
    epoch: number
    count: number
    receiptRoot: string
    auditLimit: number
  }
  proof: {
    epoch: number
    proofBinUrl?: string
    proofBinSha256?: string
  }
  verifyOut: {
    ok: boolean
    error: string | null
    count: number
    domainSize: number
    kT: number
  }
  verifiedViewCount: number
}

export type PromotionTaskProofJson = unknown

export type CreatePromotionTaskPayload = {
  postUri: string
  feedUri: string
  creatorDid: string
  verifierPublicKeyBase64?: string
  auditLimit?: number
  targetViews?: number
  metadata?: Record<string, unknown>
  [key: string]: unknown
}

export type RegisteredUserKey = {
  did: string
  publicKey: string
  createdAt?: string
  updatedAt?: string
}

export type SetupPromotionTaskResult = {
  taskId: string
  userCount: number
  domainSize: number
  importedCount: number
  ppHashHex: string
  bundleSeedBase64: string
  verifierPublicKeyBase64: string
}

export type PromotionTaskSetupStage =
  | 'user-key-load-start'
  | 'user-key-load-done'
  | 'issue-token-start'
  | 'issue-token-done'
  | 'encrypt-start'
  | 'encrypt-done'
  | 'upload-public-params-start'
  | 'upload-public-params-done'
  | 'import-receipts-start'
  | 'import-receipts-done'

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

export function listPromotionTasks(_args: {
  serviceUrl: string
  creatorDid: string
  accessJwt?: string
}): Promise<{count: number; tasks: PromotionTask[]}> {
  return Promise.reject(
    new Error('listPromotionTasks is only implemented on web'),
  )
}

export function getPromotionPostViews(_args: {
  serviceUrl: string
  postUri: string
}): Promise<PromotionPostViews> {
  return Promise.reject(
    new Error('getPromotionPostViews is only implemented on web'),
  )
}

export function getPromotionTaskAuditMaterial(_args: {
  ownerDid: string
  taskId: string
}): PromotionTaskAuditMaterial | null {
  return null
}

export function getPromotionTaskValidationState(_args: {
  ownerDid: string
  taskId: string
}): PromotionTaskValidationState {
  return {verifiedViewCount: 0}
}

export function validatePromotionTaskProof(_args: {
  serviceUrl: string
  ownerDid: string
  taskId: string
}): Promise<PromotionTaskValidationResult> {
  return Promise.reject(
    new Error('validatePromotionTaskProof is only implemented on web'),
  )
}

export function getPromotionTaskProofJson(_args: {
  serviceUrl: string
  taskId: string
}): Promise<PromotionTaskProofJson> {
  return Promise.reject(
    new Error('getPromotionTaskProofJson is only implemented on web'),
  )
}

export function getRegisteredUserCount(_args: {
  serviceUrl: string
}): Promise<number | null> {
  return Promise.reject(
    new Error('getRegisteredUserCount is only implemented on web'),
  )
}

export function listRegisteredUserKeys(_args: {
  serviceUrl: string
  order?: 'asc' | 'desc'
  limit?: number
  offset?: number
}): Promise<{
  order: 'asc' | 'desc'
  limit: number
  offset: number
  totalRegistered: number
  count: number
  keys: RegisteredUserKey[]
}> {
  return Promise.reject(
    new Error('listRegisteredUserKeys is only implemented on web'),
  )
}

export function createPromotionTask(_args: {
  serviceUrl: string
  payload: CreatePromotionTaskPayload
  accessJwt?: string
}): Promise<{taskId: string; createdAt?: string}> {
  return Promise.reject(
    new Error('createPromotionTask is only implemented on web'),
  )
}

export function setupPromotionTaskIssueChain(_args: {
  serviceUrl: string
  creatorDid: string
  taskId: string
  verifierDid: string
  expectedVerifierPublicKeyBase64: string
  accessJwt?: string
  onStage?: (stage: PromotionTaskSetupStage) => void
}): Promise<SetupPromotionTaskResult> {
  return Promise.reject(
    new Error('setupPromotionTaskIssueChain is only implemented on web'),
  )
}

export function spendEncryptedReceipt(_args: {
  serviceUrl: string
  taskId: string
  spenderDid: string
  receipt: string | Record<string, unknown>
  epoch?: number
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

export function simulatePromotionSpends(_args: {
  serviceUrl: string
  taskId: string
  accessJwt?: string
}): Promise<unknown> {
  return Promise.reject(
    new Error('simulatePromotionSpends is only implemented on web'),
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
