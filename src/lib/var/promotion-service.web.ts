import {type BskyAgent} from '@atproto/api'

import {getPromotionServicesForFeed} from '#/lib/var/promotion'
import {ensureVarUserKeypair} from '#/lib/var/user-keypair'
import {logger} from '#/logger'

const PRIVATE_KEY_PREFIX = 'var:user-key:private:'
const PUBLIC_KEY_PREFIX = 'var:user-key:public:'
const RECEIPT_ALG = 'x25519-chacha20poly1305-v1'
const RECEIPT_KDF_INFO = 'bluesky-var-receipt-v1'
const VERIFIER_PRIVATE_KEY_PREFIX = 'var:verifier-key:private:'
const X25519_SPKI_PREFIX_DER = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
])
const X25519_PKCS8_PREFIX_DER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04,
  0x22, 0x04, 0x20,
])
const ED25519_PKCS8_PREFIX_DER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
])

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

async function registerUserKey({
  serviceUrl,
  did,
  publicKey,
}: {
  serviceUrl: string
  did: string
  publicKey: string
}) {
  const registerUrl = new URL(
    `/var/user-keys/${encodeURIComponent(did)}`,
    serviceUrl,
  ).toString()
  const res = await fetch(registerUrl, {
    method: 'PUT',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({
      publicKey,
    }),
  })
  if (!res.ok) {
    throw new Error(`register user key failed (${res.status})`)
  }
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

type IssueReceipt = {
  idx: number
  did: string
  userIndex: number
  receipt: string
}

type IssueChainOutput = {
  userCount: number
  domainSize: number
  epoch: number
  ppHashHex: string
  ppBinBase64: string
  verifierSecretKeyBase64: string
  verifierPublicKeyBase64: string
  bundleSeedBase64: string
  receipts: IssueReceipt[]
}

type VerifyChainOutput = {
  ok: boolean
  error: string | null
  count: number
  domainSize: number
  kT: number
}

type EncryptedReceiptImportRow = {
  spenderDid: string
  receipt: string
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
  verifyOut: VerifyChainOutput
  verifiedViewCount: number
}

export type PromotionTaskProofJson = unknown

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

type ReceiptEnvelope = {
  alg: string
  epk: string
  nonce: string
  ct: string
  tag: string
}

type SodiumLike = {
  ready: Promise<unknown>
  crypto_scalarmult: (
    privateRaw: Uint8Array,
    publicRaw: Uint8Array,
  ) => Uint8Array
  crypto_box_keypair: () => {publicKey: Uint8Array; privateKey: Uint8Array}
  crypto_auth_hmacsha256: (message: Uint8Array, key: Uint8Array) => Uint8Array
  crypto_aead_chacha20poly1305_ietf_encrypt: (
    message: Uint8Array,
    ad: null,
    nsec: null,
    nonce: Uint8Array,
    key: Uint8Array,
  ) => Uint8Array
  crypto_aead_chacha20poly1305_ietf_decrypt: (
    nsec: null,
    cipherWithTag: Uint8Array,
    ad: null,
    nonce: Uint8Array,
    key: Uint8Array,
  ) => Uint8Array
  randombytes_buf: (len: number) => Uint8Array
}

async function loadSodium(): Promise<SodiumLike> {
  const mod = (await import('libsodium-wrappers-sumo')) as unknown
  if (isObject(mod) && 'default' in mod && mod.default) {
    return mod.default as SodiumLike
  }
  return mod as SodiumLike
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function toBase64(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer
}

function toUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(v => v.toString(16).padStart(2, '0'))
    .join('')
}

function startsWithBytes(arr: Uint8Array, prefix: Uint8Array): boolean {
  if (arr.length < prefix.length) return false
  for (let i = 0; i < prefix.length; i++) {
    if (arr[i] !== prefix[i]) return false
  }
  return true
}

function extractX25519RawKey({
  der,
  prefix,
  label,
}: {
  der: Uint8Array
  prefix: Uint8Array
  label: string
}): Uint8Array {
  if (!startsWithBytes(der, prefix)) {
    throw new Error(`Invalid${label}Prefix`)
  }
  const raw = der.slice(prefix.length)
  if (raw.length !== 32) {
    throw new Error(`Invalid${label}Length`)
  }
  return raw
}

function inspectX25519SpkiPublicKey(publicKeyBase64: string): {
  ok: boolean
  decodedLen: number
  prefixHex: string
  reason?: string
} {
  try {
    const der = fromBase64(publicKeyBase64)
    const prefix = der.slice(0, Math.min(12, der.length))
    try {
      extractX25519RawKey({
        der,
        prefix: X25519_SPKI_PREFIX_DER,
        label: 'ReceiverPublicKey',
      })
      return {
        ok: true,
        decodedLen: der.length,
        prefixHex: toHex(prefix),
      }
    } catch (err) {
      return {
        ok: false,
        decodedLen: der.length,
        prefixHex: toHex(prefix),
        reason: err instanceof Error ? err.message : String(err),
      }
    }
  } catch (err) {
    return {
      ok: false,
      decodedLen: 0,
      prefixHex: '',
      reason: err instanceof Error ? err.message : String(err),
    }
  }
}

function extractEd25519SeedFromPkcs8(pkcs8: Uint8Array): Uint8Array {
  return extractX25519RawKey({
    der: pkcs8,
    prefix: ED25519_PKCS8_PREFIX_DER,
    label: 'VerifierPrivateKey',
  })
}

function getLocalVerifierSecretKeyBase64(did: string): string {
  const privateKeyPkcs8B64 = localStorage.getItem(
    `${VERIFIER_PRIVATE_KEY_PREFIX}${did}`,
  )
  if (!privateKeyPkcs8B64) {
    throw new Error('MissingLocalVerifierPrivateKey')
  }
  const seed = extractEd25519SeedFromPkcs8(fromBase64(privateKeyPkcs8B64))
  return toBase64(seed)
}

function nextPowerOfTwo(value: number): number {
  if (!Number.isFinite(value) || value <= 1) return 1
  let n = 1
  while (n < value) n <<= 1
  return n
}

function csvEscape(value: string): string {
  return `"${value.replace(/"/g, '""')}"`
}

function buildEncryptedReceiptCsv(rows: EncryptedReceiptImportRow[]): string {
  const lines = ['spenderDid,receipt,createdAt']
  const createdAt = new Date().toISOString()
  for (const row of rows) {
    lines.push(
      `${csvEscape(row.spenderDid)},${csvEscape(row.receipt)},${csvEscape(
        createdAt,
      )}`,
    )
  }
  return lines.join('\n')
}

function normalizeEncryptedEnvelope(receiptField: string): ReceiptEnvelope {
  const raw = receiptField.trim()
  if (!raw) throw new Error('EmptyReceipt')

  try {
    const decoded = toUtf8(fromBase64(raw))
    const parsed = JSON.parse(decoded)
    if (isObject(parsed) && typeof parsed.alg === 'string') {
      return parsed as unknown as ReceiptEnvelope
    }
  } catch {
    // fallback below
  }

  const parsed = JSON.parse(raw)
  if (isObject(parsed) && typeof parsed.alg === 'string') {
    return parsed as unknown as ReceiptEnvelope
  }
  throw new Error('UnsupportedEncryptedReceiptFormat')
}

function isSpendReceiptPayload(value: unknown): value is {
  userIndex: number
  epoch: number
  rBase64: string
  sigBase64: string
} {
  if (!isObject(value)) return false
  return (
    typeof value.userIndex === 'number' &&
    typeof value.epoch === 'number' &&
    typeof value.rBase64 === 'string' &&
    typeof value.sigBase64 === 'string'
  )
}

async function decryptEnvelopeWithLocalKey({
  did,
  envelope,
}: {
  did: string
  envelope: ReceiptEnvelope
}): Promise<string> {
  try {
    return await decryptEnvelopeWithWebCrypto({did, envelope})
  } catch {
    return await decryptEnvelopeWithLibsodium({did, envelope})
  }
}

async function decryptEnvelopeWithWebCrypto({
  did,
  envelope,
}: {
  did: string
  envelope: ReceiptEnvelope
}): Promise<string> {
  if (envelope.alg !== RECEIPT_ALG) {
    throw new Error(`UnsupportedReceiptAlg:${envelope.alg}`)
  }
  const privateKeyB64 = localStorage.getItem(`${PRIVATE_KEY_PREFIX}${did}`)
  if (!privateKeyB64) throw new Error('MissingLocalPrivateKey')

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    toArrayBuffer(fromBase64(privateKeyB64)),
    {name: 'X25519'},
    false,
    ['deriveBits'],
  )
  const ephemeralPublicKey = await crypto.subtle.importKey(
    'spki',
    toArrayBuffer(fromBase64(envelope.epk)),
    {name: 'X25519'},
    false,
    [],
  )
  const sharedBits = await crypto.subtle.deriveBits(
    {name: 'X25519', public: ephemeralPublicKey},
    privateKey,
    256,
  )
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedBits,
    'HKDF',
    false,
    ['deriveBits'],
  )
  const aeadKeyBytes = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(RECEIPT_KDF_INFO),
    },
    hkdfKey,
    256,
  )
  const aeadKey = await crypto.subtle.importKey(
    'raw',
    aeadKeyBytes,
    {name: 'ChaCha20-Poly1305'},
    false,
    ['decrypt'],
  )
  const ct = fromBase64(envelope.ct)
  const tag = fromBase64(envelope.tag)
  const ciphertext = new Uint8Array(ct.length + tag.length)
  ciphertext.set(ct)
  ciphertext.set(tag, ct.length)
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'ChaCha20-Poly1305',
      iv: toArrayBuffer(fromBase64(envelope.nonce)),
    },
    aeadKey,
    ciphertext,
  )
  return toUtf8(new Uint8Array(plaintext))
}

async function decryptEnvelopeWithLibsodium({
  did,
  envelope,
}: {
  did: string
  envelope: ReceiptEnvelope
}): Promise<string> {
  if (envelope.alg !== RECEIPT_ALG) {
    throw new Error(`UnsupportedReceiptAlg:${envelope.alg}`)
  }

  const privateKeyB64 = localStorage.getItem(`${PRIVATE_KEY_PREFIX}${did}`)
  if (!privateKeyB64) throw new Error('MissingLocalPrivateKey')

  const sodiumImpl = await loadSodium()
  await sodiumImpl.ready

  const privatePkcs8 = fromBase64(privateKeyB64)
  const privateRaw = extractX25519RawKey({
    der: privatePkcs8,
    prefix: X25519_PKCS8_PREFIX_DER,
    label: 'PrivateKey',
  })
  const ephemeralSpki = fromBase64(envelope.epk)
  const ephemeralRaw = extractX25519RawKey({
    der: ephemeralSpki,
    prefix: X25519_SPKI_PREFIX_DER,
    label: 'EphemeralPublicKey',
  })

  const shared = sodiumImpl.crypto_scalarmult(privateRaw, ephemeralRaw)

  const zeroSalt = new Uint8Array(32)
  const prk = sodiumImpl.crypto_auth_hmacsha256(shared, zeroSalt)
  const info = new TextEncoder().encode(RECEIPT_KDF_INFO)
  const expandInput = new Uint8Array(info.length + 1)
  expandInput.set(info)
  expandInput[info.length] = 1
  const key = sodiumImpl.crypto_auth_hmacsha256(expandInput, prk)

  const ct = fromBase64(envelope.ct)
  const tag = fromBase64(envelope.tag)
  const ciphertextWithTag = new Uint8Array(ct.length + tag.length)
  ciphertextWithTag.set(ct)
  ciphertextWithTag.set(tag, ct.length)
  const plaintext = sodiumImpl.crypto_aead_chacha20poly1305_ietf_decrypt(
    null,
    ciphertextWithTag,
    null,
    fromBase64(envelope.nonce),
    key,
  )

  return toUtf8(plaintext)
}

type PvarWasmModule = {
  default: () => Promise<unknown>
  issue_chain: (input: unknown) => unknown
  verify_chain: (input: unknown) => unknown
}

let pvarWasmModulePromise: Promise<PvarWasmModule> | null = null

async function getPvarWasmModule(): Promise<PvarWasmModule> {
  if (!pvarWasmModulePromise) {
    pvarWasmModulePromise = (async () => {
      const mod = (await import(
        '../../../var-pkg/pvar_wasm.js'
      )) as unknown as PvarWasmModule
      await mod.default()
      return mod
    })()
  }
  return pvarWasmModulePromise
}

function parseIssueChainOutput(raw: unknown): IssueChainOutput {
  if (!isObject(raw)) {
    throw new Error('InvalidIssueChainOutput')
  }
  if (!Array.isArray(raw.receipts)) {
    throw new Error('InvalidIssueChainReceipts')
  }
  return {
    userCount: Number(raw.userCount || 0),
    domainSize: Number(raw.domainSize || 0),
    epoch: Number(raw.epoch || 0),
    ppHashHex: String(raw.ppHashHex || ''),
    ppBinBase64: String(raw.ppBinBase64 || ''),
    verifierSecretKeyBase64: String(raw.verifierSecretKeyBase64 || ''),
    verifierPublicKeyBase64: String(raw.verifierPublicKeyBase64 || ''),
    bundleSeedBase64: String(raw.bundleSeedBase64 || ''),
    receipts: raw.receipts.map(item => {
      const rec = item as Partial<IssueReceipt>
      return {
        idx: Number(rec.idx || 0),
        did: String(rec.did || ''),
        userIndex: Number(rec.userIndex || 0),
        receipt: String(rec.receipt || ''),
      }
    }),
  }
}

function parseVerifyChainOutput(raw: unknown): VerifyChainOutput {
  if (!isObject(raw)) {
    throw new Error('InvalidVerifyChainOutput')
  }
  return {
    ok: raw.ok === true,
    error: typeof raw.error === 'string' ? raw.error : null,
    count: Number(raw.count || 0),
    domainSize: Number(raw.domainSize || 0),
    kT: Number(raw.kT || 0),
  }
}

async function issueChainForTask({
  taskId,
  userDids,
  n,
  verifierSecretKeyBase64,
}: {
  taskId: string
  userDids: string[]
  n: number
  verifierSecretKeyBase64: string
}): Promise<IssueChainOutput> {
  const wasm = await getPvarWasmModule()
  const raw = wasm.issue_chain({
    userDids,
    context: taskId,
    n,
    verifierSecretKeyBase64,
  })
  const parsed = parseIssueChainOutput(raw)
  if (
    !parsed.ppHashHex ||
    !parsed.ppBinBase64 ||
    parsed.receipts.length === 0
  ) {
    throw new Error('InvalidIssueChainArtifacts')
  }
  return parsed
}

async function encryptReceiptWithWebCrypto({
  plainReceipt,
  receiverPublicKeySpkiBase64,
}: {
  plainReceipt: string
  receiverPublicKeySpkiBase64: string
}): Promise<string> {
  const receiverPublicKey = await crypto.subtle.importKey(
    'spki',
    toArrayBuffer(fromBase64(receiverPublicKeySpkiBase64)),
    {name: 'X25519'},
    false,
    [],
  )
  const generated = await crypto.subtle.generateKey({name: 'X25519'}, true, [
    'deriveBits',
  ])
  if (!('privateKey' in generated) || !('publicKey' in generated)) {
    throw new Error('InvalidEphemeralKeyPair')
  }
  const ephemeralKeyPair = generated
  const sharedBits = await crypto.subtle.deriveBits(
    {name: 'X25519', public: receiverPublicKey},
    ephemeralKeyPair.privateKey,
    256,
  )
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedBits,
    'HKDF',
    false,
    ['deriveBits'],
  )
  const aeadKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(RECEIPT_KDF_INFO),
    },
    hkdfKey,
    256,
  )
  const aeadKey = await crypto.subtle.importKey(
    'raw',
    aeadKeyBits,
    {name: 'ChaCha20-Poly1305'},
    false,
    ['encrypt'],
  )
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertextWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'ChaCha20-Poly1305',
        iv: nonce,
      },
      aeadKey,
      new TextEncoder().encode(plainReceipt),
    ),
  )
  if (ciphertextWithTag.length < 16) {
    throw new Error('InvalidEncryptedReceiptLength')
  }
  const splitAt = ciphertextWithTag.length - 16
  const ct = ciphertextWithTag.slice(0, splitAt)
  const tag = ciphertextWithTag.slice(splitAt)
  const epkSpki = await crypto.subtle.exportKey(
    'spki',
    ephemeralKeyPair.publicKey,
  )
  return JSON.stringify({
    alg: RECEIPT_ALG,
    epk: toBase64(epkSpki),
    nonce: toBase64(nonce),
    ct: toBase64(ct),
    tag: toBase64(tag),
  })
}

async function encryptReceiptWithLibsodium({
  plainReceipt,
  receiverPublicKeySpkiBase64,
}: {
  plainReceipt: string
  receiverPublicKeySpkiBase64: string
}): Promise<string> {
  const sodiumImpl = await loadSodium()
  await sodiumImpl.ready

  const receiverRaw = extractX25519RawKey({
    der: fromBase64(receiverPublicKeySpkiBase64),
    prefix: X25519_SPKI_PREFIX_DER,
    label: 'ReceiverPublicKey',
  })
  const eph = sodiumImpl.crypto_box_keypair()
  const shared = sodiumImpl.crypto_scalarmult(eph.privateKey, receiverRaw)

  const zeroSalt = new Uint8Array(32)
  const prk = sodiumImpl.crypto_auth_hmacsha256(shared, zeroSalt)
  const info = new TextEncoder().encode(RECEIPT_KDF_INFO)
  const expandInput = new Uint8Array(info.length + 1)
  expandInput.set(info)
  expandInput[info.length] = 1
  const key = sodiumImpl.crypto_auth_hmacsha256(expandInput, prk)

  const nonce = sodiumImpl.randombytes_buf(12)
  const ciphertextWithTag =
    sodiumImpl.crypto_aead_chacha20poly1305_ietf_encrypt(
      new TextEncoder().encode(plainReceipt),
      null,
      null,
      nonce,
      key,
    )
  if (ciphertextWithTag.length < 16) {
    throw new Error('InvalidEncryptedReceiptLength')
  }
  const splitAt = ciphertextWithTag.length - 16
  const ct = ciphertextWithTag.slice(0, splitAt)
  const tag = ciphertextWithTag.slice(splitAt)

  const epkDer = new Uint8Array(
    X25519_SPKI_PREFIX_DER.length + eph.publicKey.length,
  )
  epkDer.set(X25519_SPKI_PREFIX_DER)
  epkDer.set(eph.publicKey, X25519_SPKI_PREFIX_DER.length)

  return JSON.stringify({
    alg: RECEIPT_ALG,
    epk: toBase64(epkDer),
    nonce: toBase64(nonce),
    ct: toBase64(ct),
    tag: toBase64(tag),
  })
}

async function encryptReceiptForUser({
  plainReceipt,
  receiverPublicKeySpkiBase64,
}: {
  plainReceipt: string
  receiverPublicKeySpkiBase64: string
}): Promise<string> {
  try {
    return await encryptReceiptWithWebCrypto({
      plainReceipt,
      receiverPublicKeySpkiBase64,
    })
  } catch {
    return await encryptReceiptWithLibsodium({
      plainReceipt,
      receiverPublicKeySpkiBase64,
    })
  }
}

function authHeaders(accessJwt: string | undefined): HeadersInit {
  return accessJwt
    ? {
        authorization: `Bearer ${accessJwt}`,
        'content-type': 'application/json',
      }
    : {'content-type': 'application/json'}
}

export async function requestEncryptedReceipt({
  serviceUrl,
  taskId,
  spenderDid,
  accessJwt,
}: {
  serviceUrl: string
  taskId: string
  spenderDid: string
  accessJwt?: string
}): Promise<EncryptedReceiptResponse> {
  const url = new URL(
    `/var/tasks/${encodeURIComponent(taskId)}/encrypted-receipts`,
    serviceUrl,
  ).toString()
  const res = await fetch(url, {
    method: 'POST',
    headers: authHeaders(accessJwt),
    body: JSON.stringify({spenderDid}),
  })
  if (!res.ok) {
    throw new Error(`request encrypted receipt failed (${res.status})`)
  }
  return (await res.json()) as EncryptedReceiptResponse
}

export async function listPromotionTasks({
  serviceUrl,
  creatorDid,
  accessJwt,
}: {
  serviceUrl: string
  creatorDid: string
  accessJwt?: string
}): Promise<{count: number; tasks: PromotionTask[]}> {
  const url = new URL('/var/tasks', serviceUrl)
  url.searchParams.set('creatorDid', creatorDid)
  const headers = accessJwt ? {authorization: `Bearer ${accessJwt}`} : undefined
  const res = await fetch(url.toString(), {
    method: 'GET',
    headers,
  })
  if (!res.ok) {
    throw new Error(`list promotion tasks failed (${res.status})`)
  }
  const payload = (await res.json()) as unknown
  if (!isObject(payload) || !Array.isArray(payload.tasks)) {
    return {count: 0, tasks: []}
  }
  return {
    count:
      typeof payload.count === 'number' && Number.isFinite(payload.count)
        ? payload.count
        : payload.tasks.length,
    tasks: payload.tasks as PromotionTask[],
  }
}

export async function getPromotionPostViews({
  serviceUrl,
  postUri,
}: {
  serviceUrl: string
  postUri: string
}): Promise<PromotionPostViews> {
  const url = new URL('/var/posts/views', serviceUrl)
  url.searchParams.set('postUri', postUri)
  const res = await fetch(url.toString(), {
    method: 'GET',
  })
  if (!res.ok) {
    throw new Error(`promotion views request failed (${res.status})`)
  }
  const payload = (await res.json()) as unknown
  if (!isObject(payload)) {
    return {postUri, viewCount: 0}
  }
  const rawViewCount = payload.viewCount
  const rawTaskCount = payload.taskCount
  return {
    postUri,
    viewCount:
      typeof rawViewCount === 'number' && Number.isFinite(rawViewCount)
        ? Math.max(0, Math.floor(rawViewCount))
        : 0,
    taskCount:
      typeof rawTaskCount === 'number' && Number.isFinite(rawTaskCount)
        ? Math.max(0, Math.floor(rawTaskCount))
        : undefined,
  }
}

export async function validatePromotionTaskProof({
  serviceUrl,
  ownerDid,
  taskId,
}: {
  serviceUrl: string
  ownerDid: string
  taskId: string
}): Promise<PromotionTaskValidationResult> {
  const audit = getPromotionTaskAuditMaterial({ownerDid, taskId})
  if (!audit) {
    throw new Error('MissingLocalTaskAuditMaterial')
  }

  const commitmentsUrl = new URL(
    `/var/tasks/${encodeURIComponent(taskId)}/commitments`,
    serviceUrl,
  ).toString()
  const commitmentsRes = await fetch(commitmentsUrl, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({ppHash: audit.ppHashHex}),
  })
  if (!commitmentsRes.ok) {
    throw new Error(`commitments failed (${commitmentsRes.status})`)
  }
  const commitments = (await commitmentsRes.json()) as {
    epoch: number
    count: number
    receiptRoot: string
    auditLimit: number
  }

  const proofsUrl = new URL(
    `/var/tasks/${encodeURIComponent(taskId)}/proofs`,
    serviceUrl,
  ).toString()
  const proofRes = await fetch(proofsUrl, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({
      bundleSeed: audit.bundleSeedBase64,
      epoch: commitments.epoch,
    }),
  })
  if (!proofRes.ok) {
    throw new Error(`proof failed (${proofRes.status})`)
  }
  const proof = (await proofRes.json()) as {
    epoch: number
    proofBinUrl?: string
    proofBinSha256?: string
  }
  if (proof.epoch !== commitments.epoch) {
    throw new Error(
      `epoch mismatch: commitments=${commitments.epoch}, proof=${proof.epoch}`,
    )
  }
  if (!proof.proofBinUrl) {
    throw new Error('MissingProofBinUrl')
  }

  const proofBinRes = await fetch(proof.proofBinUrl)
  if (!proofBinRes.ok) {
    throw new Error(`download proof.bin failed (${proofBinRes.status})`)
  }
  const proofBinBase64 = toBase64(await proofBinRes.arrayBuffer())

  const wasm = await getPvarWasmModule()
  const verifyOut = parseVerifyChainOutput(
    wasm.verify_chain({
      ppBinBase64: audit.ppBinBase64,
      bundleSeedBase64: audit.bundleSeedBase64,
      proofBinBase64,
    }),
  )
  if (!verifyOut.ok) {
    throw new Error(
      `local verify failed: ${verifyOut.error ?? 'unknown error'}`,
    )
  }

  const validationState = savePromotionTaskValidationState({
    ownerDid,
    taskId,
    verifiedViewCount: verifyOut.count,
  })

  return {
    commitments,
    proof,
    verifyOut,
    verifiedViewCount: validationState.verifiedViewCount,
  }
}

export async function getPromotionTaskProofJson({
  serviceUrl,
  taskId,
}: {
  serviceUrl: string
  taskId: string
}): Promise<PromotionTaskProofJson> {
  const proofJsonUrl = new URL(
    `/var/tasks/${encodeURIComponent(taskId)}/proof.json`,
    serviceUrl,
  ).toString()
  const res = await fetch(proofJsonUrl, {
    method: 'GET',
  })
  if (!res.ok) {
    throw new Error(`get proof.json failed (${res.status})`)
  }
  return (await res.json()) as PromotionTaskProofJson
}

export async function getRegisteredUserCount({
  serviceUrl,
}: {
  serviceUrl: string
}): Promise<number | null> {
  const url = new URL('/var/user-keys', serviceUrl)
  url.searchParams.set('order', 'asc')
  url.searchParams.set('limit', '1')
  url.searchParams.set('offset', '0')
  const res = await fetch(url.toString(), {
    method: 'GET',
  })
  if (!res.ok) {
    throw new Error(`get registered user count failed (${res.status})`)
  }
  const payload = (await res.json()) as unknown
  if (!isObject(payload)) return null

  const totalRegistered = payload.totalRegistered
  if (typeof totalRegistered === 'number' && Number.isFinite(totalRegistered)) {
    return Math.max(0, Math.floor(totalRegistered))
  }

  const count = payload.count
  if (typeof count === 'number' && Number.isFinite(count)) {
    return Math.max(0, Math.floor(count))
  }

  const keys = payload.keys
  if (Array.isArray(keys)) {
    return keys.length
  }

  return null
}

export async function listRegisteredUserKeys({
  serviceUrl,
  order = 'asc',
  limit = 5000,
  offset = 0,
}: {
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
  const url = new URL('/var/user-keys', serviceUrl)
  url.searchParams.set('order', order)
  url.searchParams.set('limit', String(limit))
  url.searchParams.set('offset', String(offset))
  const res = await fetch(url.toString(), {
    method: 'GET',
  })
  if (!res.ok) {
    throw new Error(`list registered user keys failed (${res.status})`)
  }
  const payload = (await res.json()) as unknown
  if (!isObject(payload) || !Array.isArray(payload.keys)) {
    return {
      order,
      limit,
      offset,
      totalRegistered: 0,
      count: 0,
      keys: [],
    }
  }
  return {
    order,
    limit,
    offset,
    totalRegistered: Number(payload.totalRegistered || payload.count || 0),
    count: Number(payload.count || payload.keys.length || 0),
    keys: payload.keys as RegisteredUserKey[],
  }
}

async function fetchAllRegisteredUserKeys(
  serviceUrl: string,
): Promise<RegisteredUserKey[]> {
  const all: RegisteredUserKey[] = []
  const pageSize = 5000
  let offset = 0
  while (true) {
    const page = await listRegisteredUserKeys({
      serviceUrl,
      order: 'asc',
      limit: pageSize,
      offset,
    })
    if (!page.keys.length) break
    all.push(...page.keys)
    offset += page.keys.length
    if (page.keys.length < pageSize) break
  }
  return all.filter(
    key => typeof key.did === 'string' && typeof key.publicKey === 'string',
  )
}

async function uploadPublicParams({
  serviceUrl,
  creatorDid,
  ppHash,
  n,
  ppBinBase64,
  accessJwt,
}: {
  serviceUrl: string
  creatorDid: string
  ppHash: string
  n: number
  ppBinBase64: string
  accessJwt?: string
}): Promise<void> {
  const url = new URL(
    `/var/creators/${encodeURIComponent(creatorDid)}/public-params/${encodeURIComponent(
      ppHash,
    )}`,
    serviceUrl,
  )
  const form = new FormData()
  form.append('ppHash', ppHash)
  form.append('n', String(n))
  form.append(
    'ppBinFile',
    new Blob([toArrayBuffer(fromBase64(ppBinBase64))]),
    `${ppHash}.bin`,
  )
  const headers = accessJwt ? {authorization: `Bearer ${accessJwt}`} : undefined
  const res = await fetch(url.toString(), {
    method: 'PUT',
    headers,
    body: form,
  })
  if (!res.ok) {
    throw new Error(`upload public params failed (${res.status})`)
  }
}

async function importEncryptedReceiptsCsv({
  serviceUrl,
  taskId,
  csvContent,
  accessJwt,
}: {
  serviceUrl: string
  taskId: string
  csvContent: string
  accessJwt?: string
}): Promise<void> {
  const url = new URL(
    `/var/tasks/${encodeURIComponent(taskId)}/encrypted-receipts/imports`,
    serviceUrl,
  )
  url.searchParams.set('format', 'csv')
  url.searchParams.set('mode', 'merge')
  const headers: Record<string, string> = {
    'content-type': 'text/csv',
  }
  if (accessJwt) headers.authorization = `Bearer ${accessJwt}`
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body: csvContent,
  })
  if (!res.ok) {
    throw new Error(`import encrypted receipts failed (${res.status})`)
  }
}

function saveTaskAuditMaterial({
  ownerDid,
  taskId,
  bundleSeedBase64,
  ppHashHex,
  ppBinBase64,
  verifierSecretKeyBase64,
}: {
  ownerDid: string
  taskId: string
  bundleSeedBase64: string
  ppHashHex: string
  ppBinBase64: string
  verifierSecretKeyBase64: string
}) {
  const storageKey = `var:task-audit:${ownerDid}:${taskId}`
  localStorage.setItem(
    storageKey,
    JSON.stringify({
      taskId,
      bundleSeedBase64,
      ppHashHex,
      ppBinBase64,
      verifierSecretKeyBase64,
      savedAt: new Date().toISOString(),
    }),
  )
}

function getTaskAuditMaterialStorageKey(
  ownerDid: string,
  taskId: string,
): string {
  return `var:task-audit:${ownerDid}:${taskId}`
}

function getTaskValidationStorageKey(ownerDid: string, taskId: string): string {
  return `var:task-validate:${ownerDid}:${taskId}`
}

export function getPromotionTaskAuditMaterial({
  ownerDid,
  taskId,
}: {
  ownerDid: string
  taskId: string
}): PromotionTaskAuditMaterial | null {
  const raw = localStorage.getItem(
    getTaskAuditMaterialStorageKey(ownerDid, taskId),
  )
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Partial<PromotionTaskAuditMaterial>
    if (
      typeof parsed.taskId !== 'string' ||
      typeof parsed.bundleSeedBase64 !== 'string' ||
      typeof parsed.ppHashHex !== 'string' ||
      typeof parsed.ppBinBase64 !== 'string' ||
      typeof parsed.verifierSecretKeyBase64 !== 'string'
    ) {
      return null
    }
    return {
      taskId: parsed.taskId,
      bundleSeedBase64: parsed.bundleSeedBase64,
      ppHashHex: parsed.ppHashHex,
      ppBinBase64: parsed.ppBinBase64,
      verifierSecretKeyBase64: parsed.verifierSecretKeyBase64,
      savedAt: typeof parsed.savedAt === 'string' ? parsed.savedAt : undefined,
    }
  } catch {
    return null
  }
}

export function getPromotionTaskValidationState({
  ownerDid,
  taskId,
}: {
  ownerDid: string
  taskId: string
}): PromotionTaskValidationState {
  const raw = localStorage.getItem(
    getTaskValidationStorageKey(ownerDid, taskId),
  )
  if (!raw) return {verifiedViewCount: 0}
  try {
    const parsed = JSON.parse(raw) as Partial<PromotionTaskValidationState>
    return {
      verifiedViewCount:
        typeof parsed.verifiedViewCount === 'number' &&
        Number.isFinite(parsed.verifiedViewCount)
          ? Math.max(0, Math.floor(parsed.verifiedViewCount))
          : 0,
      lastValidatedAt:
        typeof parsed.lastValidatedAt === 'string'
          ? parsed.lastValidatedAt
          : undefined,
    }
  } catch {
    return {verifiedViewCount: 0}
  }
}

function savePromotionTaskValidationState({
  ownerDid,
  taskId,
  verifiedViewCount,
}: {
  ownerDid: string
  taskId: string
  verifiedViewCount: number
}): PromotionTaskValidationState {
  const next = {
    verifiedViewCount: Math.max(0, Math.floor(verifiedViewCount)),
    lastValidatedAt: new Date().toISOString(),
  }
  localStorage.setItem(
    getTaskValidationStorageKey(ownerDid, taskId),
    JSON.stringify(next),
  )
  return next
}

export async function createPromotionTask({
  serviceUrl,
  payload,
  accessJwt,
}: {
  serviceUrl: string
  payload: CreatePromotionTaskPayload
  accessJwt?: string
}): Promise<{taskId: string; createdAt?: string}> {
  const url = new URL('/var/tasks', serviceUrl).toString()
  const res = await fetch(url, {
    method: 'POST',
    headers: authHeaders(accessJwt),
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    throw new Error(`create promotion task failed (${res.status})`)
  }
  return (await res.json()) as {taskId: string; createdAt?: string}
}

export async function setupPromotionTaskIssueChain({
  serviceUrl,
  creatorDid,
  taskId,
  verifierDid,
  expectedVerifierPublicKeyBase64,
  accessJwt,
  onStage,
}: {
  serviceUrl: string
  creatorDid: string
  taskId: string
  verifierDid: string
  expectedVerifierPublicKeyBase64: string
  accessJwt?: string
  onStage?: (stage: PromotionTaskSetupStage) => void
}): Promise<SetupPromotionTaskResult> {
  onStage?.('user-key-load-start')
  console.log('new promotion: user key load start', {
    taskId,
    serviceUrl,
  })
  const userKeys = await fetchAllRegisteredUserKeys(serviceUrl)
  onStage?.('user-key-load-done')
  console.log('new promotion: user key load done', {
    taskId,
    serviceUrl,
    userKeyCount: userKeys.length,
  })
  if (userKeys.length === 0) {
    throw new Error('NoRegisteredUserKeys')
  }
  const verifierSecretKeyBase64 = getLocalVerifierSecretKeyBase64(verifierDid)
  const userDids = userKeys.map(item => item.did)
  const n = nextPowerOfTwo(userDids.length)

  onStage?.('issue-token-start')
  console.log('new promotion: issue token start', {
    taskId,
    serviceUrl,
    userCount: userDids.length,
    n,
  })
  const issue = await issueChainForTask({
    taskId,
    userDids,
    n,
    verifierSecretKeyBase64,
  })
  onStage?.('issue-token-done')
  console.log('new promotion: issue token done', {
    taskId,
    serviceUrl,
    receiptCount: issue.receipts.length,
    ppHashHex: issue.ppHashHex,
  })
  if (issue.verifierPublicKeyBase64 !== expectedVerifierPublicKeyBase64) {
    throw new Error('VerifierKeyMismatchForIssueChain')
  }

  onStage?.('upload-public-params-start')
  console.log('new promotion: upload public params start', {
    taskId,
    serviceUrl,
    ppHashHex: issue.ppHashHex,
  })
  await uploadPublicParams({
    serviceUrl,
    creatorDid,
    ppHash: issue.ppHashHex,
    n: issue.domainSize,
    ppBinBase64: issue.ppBinBase64,
    accessJwt,
  })
  onStage?.('upload-public-params-done')
  console.log('new promotion: upload public params done', {
    taskId,
    serviceUrl,
    ppHashHex: issue.ppHashHex,
  })

  const keyByDid = new Map(userKeys.map(item => [item.did, item.publicKey]))
  for (const item of userKeys) {
    const inspected = inspectX25519SpkiPublicKey(item.publicKey)
    if (!inspected.ok) {
      console.error('new promotion: invalid receiver public key', {
        taskId,
        serviceUrl,
        did: item.did,
        publicKey: item.publicKey,
        decodedLen: inspected.decodedLen,
        prefixHex: inspected.prefixHex,
        reason: inspected.reason,
      })
    }
  }
  onStage?.('encrypt-start')
  console.log('new promotion: encrypt receipts start', {
    taskId,
    serviceUrl,
    receiptCount: issue.receipts.length,
  })
  const encryptedRows = await Promise.all(
    issue.receipts.map(async receipt => {
      const publicKey = keyByDid.get(receipt.did)
      if (!publicKey) {
        throw new Error(`MissingUserPublicKey:${receipt.did}`)
      }
      let encrypted: string
      try {
        encrypted = await encryptReceiptForUser({
          plainReceipt: receipt.receipt,
          receiverPublicKeySpkiBase64: publicKey,
        })
      } catch (err) {
        const inspected = inspectX25519SpkiPublicKey(publicKey)
        console.error('new promotion: failed to encrypt for receiver', {
          taskId,
          serviceUrl,
          did: receipt.did,
          publicKey,
          decodedLen: inspected.decodedLen,
          prefixHex: inspected.prefixHex,
          reason: err instanceof Error ? err.message : String(err),
          keyInspectReason: inspected.reason,
        })
        throw err
      }
      return {
        spenderDid: receipt.did,
        receipt: encrypted,
      }
    }),
  )
  onStage?.('encrypt-done')
  console.log('new promotion: encrypt receipts done', {
    taskId,
    serviceUrl,
    encryptedCount: encryptedRows.length,
  })

  const csv = buildEncryptedReceiptCsv(encryptedRows)
  onStage?.('import-receipts-start')
  console.log('new promotion: import encrypted receipts start', {
    taskId,
    serviceUrl,
    encryptedCount: encryptedRows.length,
  })
  await importEncryptedReceiptsCsv({
    serviceUrl,
    taskId,
    csvContent: csv,
    accessJwt,
  })
  onStage?.('import-receipts-done')
  console.log('new promotion: import encrypted receipts done', {
    taskId,
    serviceUrl,
  })

  saveTaskAuditMaterial({
    ownerDid: creatorDid,
    taskId,
    bundleSeedBase64: issue.bundleSeedBase64,
    ppHashHex: issue.ppHashHex,
    ppBinBase64: issue.ppBinBase64,
    verifierSecretKeyBase64,
  })

  return {
    taskId,
    userCount: issue.userCount,
    domainSize: issue.domainSize,
    importedCount: encryptedRows.length,
    ppHashHex: issue.ppHashHex,
    bundleSeedBase64: issue.bundleSeedBase64,
    verifierPublicKeyBase64: issue.verifierPublicKeyBase64,
  }
}

export async function spendEncryptedReceipt({
  serviceUrl,
  taskId,
  spenderDid,
  receipt,
  epoch,
  accessJwt,
}: {
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
  const url = new URL(
    `/var/tasks/${encodeURIComponent(taskId)}/spends`,
    serviceUrl,
  ).toString()
  const receiptPayload =
    typeof receipt === 'string' ? receipt : JSON.stringify(receipt)
  const body: Record<string, unknown> = {
    spenderDid,
    receipt: receiptPayload,
  }
  if (typeof epoch === 'number' && Number.isFinite(epoch)) {
    body.epoch = epoch
  }
  const res = await fetch(url, {
    method: 'POST',
    headers: authHeaders(accessJwt),
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    throw new Error(`spend receipt failed (${res.status})`)
  }
  return (await res.json()) as {
    taskId: string
    spenderDid: string
    r: string
    spentAt: string
    duplicate: boolean
  }
}

export async function simulatePromotionSpends({
  serviceUrl,
  taskId,
  accessJwt,
}: {
  serviceUrl: string
  taskId: string
  accessJwt?: string
}): Promise<unknown> {
  const url = new URL('/test/simulate-spends', serviceUrl).toString()
  const res = await fetch(url, {
    method: 'POST',
    headers: authHeaders(accessJwt),
    body: JSON.stringify({
      taskId,
    }),
  })
  if (!res.ok) {
    throw new Error(`simulate spends failed (${res.status})`)
  }
  return (await res.json().catch(() => ({}))) as unknown
}

export async function autoSpendPromotionReceipt({
  serviceUrl,
  taskId,
  spenderDid,
  accessJwt,
}: {
  serviceUrl: string
  taskId: string
  spenderDid: string
  accessJwt?: string
}): Promise<{spent: boolean; reason?: string}> {
  const response = await requestEncryptedReceipt({
    serviceUrl,
    taskId,
    spenderDid,
    accessJwt,
  })
  if (!response.receipt) return {spent: false, reason: 'missing-receipt'}

  let plainReceipt: string
  try {
    const envelope = normalizeEncryptedEnvelope(response.receipt)
    plainReceipt = await decryptEnvelopeWithLocalKey({
      did: spenderDid,
      envelope,
    })
  } catch (err) {
    console.error('Failed to decrypt receipt', {
      message: err instanceof Error ? err.message : String(err),
    })
    return {
      spent: false,
      reason: err instanceof Error ? err.message : String(err),
    }
  }

  console.log('Decrypted receipt:', plainReceipt)

  let parsed: unknown
  try {
    parsed = JSON.parse(plainReceipt)
  } catch {
    return {spent: false, reason: 'invalid-plain-receipt-json'}
  }
  if (!isSpendReceiptPayload(parsed)) {
    return {spent: false, reason: 'invalid-plain-receipt-payload'}
  }

  await spendEncryptedReceipt({
    serviceUrl,
    taskId,
    spenderDid,
    receipt: plainReceipt,
    epoch: parsed.epoch,
    accessJwt,
  })
  return {spent: true}
}

export async function notifyPromotionServiceForSavedFeeds({
  agent,
  savedFeeds,
}: {
  agent: BskyAgent
  savedFeeds: Array<{type: string; value: string}>
}): Promise<void> {
  try {
    const did = agent.session?.did
    if (!did) return

    const feedUris = Array.from(
      new Set(
        savedFeeds
          .filter(feed => feed.type === 'feed')
          .map(feed => feed.value)
          .filter(value => value.includes('app.bsky.feed.generator')),
      ),
    )

    if (feedUris.length === 0) return

    await ensureVarUserKeypair(agent)
    const publicKey = localStorage.getItem(`${PUBLIC_KEY_PREFIX}${did}`)
    if (!publicKey) {
      logger.debug('promotion service notify: missing local public key', {did})
      return
    }

    logger.debug('promotion service notify: start', {
      did,
      feedUriCount: feedUris.length,
    })

    await Promise.all(
      feedUris.map(async feedUri => {
        try {
          const services = await getPromotionServicesForFeed({
            agent,
            feedUri,
          })
          if (services.length === 0) {
            logger.debug('promotion service notify: no service URL', {
              did,
              feedUri,
            })
            return
          }
          await Promise.all(
            services.map(async service => {
              const serviceUrl = service.serviceEndpoint
              await registerUserKey({
                serviceUrl,
                did,
                publicKey,
              })
              logger.debug('promotion service notify: user key registered', {
                did,
                feedUri,
                serviceUrl,
                recordUri: service.recordUri,
              })
            }),
          )
        } catch (err) {
          logger.error('promotion service: failed to send key', {
            feedUri,
            message: err instanceof Error ? err.message : String(err),
          })
        }
      }),
    )
  } catch (err) {
    logger.error('promotion service: unexpected failure', {
      message: err instanceof Error ? err.message : String(err),
    })
  }
}
