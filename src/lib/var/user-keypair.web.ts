import {type AtpAgent} from '@atproto/api'

import {ensureVarDerivedKeyMaterial} from '#/lib/var/keyring'
import {logger} from '#/logger'

const COLLECTION = 'com.hackingdecentralized.var.userKey'
const RKEY = 'self'
const RECEIPT_ALG = 'x25519-chacha20poly1305-v1'
const RECEIPT_KDF_INFO = 'bluesky-var-receipt-v1'
const PUBLIC_KEY_ENCODING = 'base64-spki-der'

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

export async function ensureVarUserKeypair(agent: AtpAgent): Promise<void> {
  try {
    const did = agent.session?.did
    if (!did) return

    const material = await ensureVarDerivedKeyMaterial(did)
    const publicSpkiB64 = material.userPublicKeySpkiBase64

    let shouldPublish = true
    try {
      const existing = await agent.api.com.atproto.repo.getRecord({
        repo: did,
        collection: COLLECTION,
        rkey: RKEY,
      })
      const value = existing.data.value
      if (isObject(value)) {
        const existingPublicKey =
          typeof value.publicKey === 'string' ? value.publicKey : ''
        const existingEncoding =
          typeof value.encoding === 'string' ? value.encoding : ''
        shouldPublish =
          existingPublicKey !== publicSpkiB64 ||
          existingEncoding !== PUBLIC_KEY_ENCODING
      }
    } catch {
      shouldPublish = true
    }

    if (!shouldPublish) {
      return
    }

    const now = new Date().toISOString()
    await agent.com.atproto.repo.putRecord({
      repo: did,
      collection: COLLECTION,
      rkey: RKEY,
      record: {
        $type: COLLECTION,
        algorithm: RECEIPT_ALG,
        encoding: PUBLIC_KEY_ENCODING,
        publicKey: publicSpkiB64,
        kdf: 'HKDF-SHA256',
        kdfInfo: RECEIPT_KDF_INFO,
        aead: 'CHACHA20-POLY1305',
        createdAt: now,
        updatedAt: now,
      },
    })
  } catch (err) {
    logger.error('var keypair: failed to initialize or publish keypair', {
      message: err instanceof Error ? err.message : String(err),
    })
  }
}
