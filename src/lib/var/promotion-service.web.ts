import {type BskyAgent} from '@atproto/api'

import {getPromotionServiceEndpointForFeed} from '#/lib/var/promotion'
import {logger} from '#/logger'

const PRIVATE_KEY_PREFIX = 'var:user-key:private:'
const USER_KEY_COLLECTION = 'com.hackingdecentralized.var.userKey'
const USER_KEY_RKEY = 'self'
const RECEIPT_ALG = 'x25519-chacha20poly1305-v1'
const RECEIPT_KDF_INFO = 'bluesky-var-receipt-v1'
const X25519_SPKI_PREFIX_DER = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
])
const X25519_PKCS8_PREFIX_DER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04,
  0x22, 0x04, 0x20,
])
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

async function getOwnPublicKey(agent: BskyAgent): Promise<string | null> {
  const did = agent.session?.did
  if (!did) return null

  try {
    const {data} = await agent.api.com.atproto.repo.getRecord({
      repo: did,
      collection: USER_KEY_COLLECTION,
      rkey: USER_KEY_RKEY,
    })
    const value = data.value
    if (isObject(value)) {
      return typeof value.publicKey === 'string' ? value.publicKey : null
    }
    return null
  } catch {
    return null
  }
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
  crypto_auth_hmacsha256: (message: Uint8Array, key: Uint8Array) => Uint8Array
  crypto_aead_chacha20poly1305_ietf_decrypt: (
    nsec: null,
    cipherWithTag: Uint8Array,
    ad: null,
    nonce: Uint8Array,
    key: Uint8Array,
  ) => Uint8Array
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

function toUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
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
    fromBase64(privateKeyB64),
    {name: 'X25519'},
    false,
    ['deriveBits'],
  )
  const ephemeralPublicKey = await crypto.subtle.importKey(
    'spki',
    fromBase64(envelope.epk),
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
      iv: fromBase64(envelope.nonce),
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

export async function spendEncryptedReceipt({
  serviceUrl,
  taskId,
  spenderDid,
  receipt,
  accessJwt,
}: {
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
  const url = new URL(
    `/var/tasks/${encodeURIComponent(taskId)}/spends`,
    serviceUrl,
  ).toString()
  const receiptPayload =
    typeof receipt === 'string' ? receipt : JSON.stringify(receipt)
  const res = await fetch(url, {
    method: 'POST',
    headers: authHeaders(accessJwt),
    body: JSON.stringify({
      spenderDid,
      receipt: receiptPayload,
    }),
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

    const publicKey = await getOwnPublicKey(agent)
    if (!publicKey) {
      logger.debug('promotion service notify: missing public key record', {did})
      return
    }

    logger.debug('promotion service notify: start', {
      did,
      feedUriCount: feedUris.length,
    })

    await Promise.all(
      feedUris.map(async feedUri => {
        try {
          const serviceUrl = await getPromotionServiceEndpointForFeed({
            agent,
            feedUri,
          })
          if (!serviceUrl) {
            logger.debug('promotion service notify: no service URL', {
              did,
              feedUri,
            })
            return
          }
          await registerUserKey({
            serviceUrl,
            did,
            publicKey,
          })
          logger.debug('promotion service notify: user key registered', {
            did,
            feedUri,
            serviceUrl,
          })
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
