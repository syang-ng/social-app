import {type AtpAgent} from '@atproto/api'

import {logger} from '#/logger'

const PRIVATE_KEY_PREFIX = 'var:user-key:private:'
const COLLECTION = 'com.hackingdecentralized.var.userKey'
const RKEY = 'self'
const RECEIPT_ALG = 'x25519-chacha20poly1305-v1'
const RECEIPT_KDF_INFO = 'bluesky-var-receipt-v1'

function toBase64(bytes: ArrayBuffer): string {
  const arr = new Uint8Array(bytes)
  let binary = ''
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i])
  }
  return btoa(binary)
}

export async function ensureVarUserKeypair(agent: AtpAgent): Promise<void> {
  try {
    const did = agent.session?.did
    if (!did) return

    const storageKey = `${PRIVATE_KEY_PREFIX}${did}`
    const existing = localStorage.getItem(storageKey)
    if (existing) {
      return
    }

    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'X25519',
      },
      true,
      ['deriveBits'],
    )

    const privatePkcs8 = await crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey,
    )
    const publicRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey)
    const privatePkcs8B64 = toBase64(privatePkcs8)
    const publicRawB64 = toBase64(publicRaw)

    localStorage.setItem(storageKey, privatePkcs8B64)

    const now = new Date().toISOString()
    await agent.com.atproto.repo.putRecord({
      repo: did,
      collection: COLLECTION,
      rkey: RKEY,
      record: {
        $type: COLLECTION,
        algorithm: RECEIPT_ALG,
        encoding: 'base64-raw',
        publicKey: publicRawB64,
        kdf: 'HKDF-SHA256',
        kdfInfo: RECEIPT_KDF_INFO,
        aead: 'CHACHA20-POLY1305',
        createdAt: now,
      },
    })
  } catch (err) {
    logger.error('var keypair: failed to initialize or publish keypair', {
      message: err instanceof Error ? err.message : String(err),
    })
  }
}
