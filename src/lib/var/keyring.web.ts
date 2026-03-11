import ENGLISH_WORDLIST from 'bip39/src/wordlists/english.json'

import {logger} from '#/logger'

const MASTER_SEED_PREFIX = 'var:master-seed:'
const USER_PRIVATE_KEY_PREFIX = 'var:user-key:private:'
const USER_PUBLIC_KEY_PREFIX = 'var:user-key:public:'
const VERIFIER_PRIVATE_KEY_PREFIX = 'var:verifier-key:private:'
const VERIFIER_PUBLIC_KEY_PREFIX = 'var:verifier-key:public:'

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

const USER_KEY_INFO = 'bluesky-var/user-x25519/v1'
const VERIFIER_KEY_INFO = 'bluesky-var/verifier-ed25519/v1'
const BIP39_WORDLIST = ENGLISH_WORDLIST as string[]

type SodiumKeyringLike = {
  ready: Promise<unknown>
  crypto_box_seed_keypair: (seed: Uint8Array) => {
    publicKey: Uint8Array
    privateKey: Uint8Array
  }
  crypto_sign_seed_keypair: (seed: Uint8Array) => {
    publicKey: Uint8Array
    privateKey: Uint8Array
  }
}

export type VarDerivedKeyMaterial = {
  masterSeedBase64: string
  userPrivateKeyPkcs8Base64: string
  userPublicKeySpkiBase64: string
  verifierPrivateKeyPkcs8Base64: string
  verifierPublicKeyBase64: string
}

function toBase64(bytes: Uint8Array | ArrayBuffer): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i])
  }
  return btoa(binary)
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer
}

function lpad(value: string, pad: string, length: number): string {
  let out = value
  while (out.length < length) {
    out = `${pad}${out}`
  }
  return out
}

function bytesToBinary(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => lpad(byte.toString(2), '0', 8))
    .join('')
}

function binaryToByte(binary: string): number {
  return Number.parseInt(binary, 2)
}

async function loadSodium(): Promise<SodiumKeyringLike> {
  const mod = (await import('libsodium-wrappers-sumo')) as unknown
  if (
    typeof mod === 'object' &&
    mod !== null &&
    'default' in mod &&
    mod.default
  ) {
    return mod.default as SodiumKeyringLike
  }
  return mod as SodiumKeyringLike
}

async function deriveSubSeed(
  masterSeed: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(masterSeed),
    'HKDF',
    false,
    ['deriveBits'],
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array([]),
      info: new TextEncoder().encode(info),
    },
    hkdfKey,
    256,
  )
  return new Uint8Array(bits)
}

async function deriveChecksumBits(entropy: Uint8Array): Promise<string> {
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', toArrayBuffer(entropy)),
  )
  return bytesToBinary(hash).slice(0, entropy.length / 4)
}

async function entropyToMnemonicWords(entropy: Uint8Array): Promise<string> {
  if (entropy.length !== 32) {
    throw new Error('InvalidVarSeedLength')
  }
  const entropyBits = bytesToBinary(entropy)
  const checksumBits = await deriveChecksumBits(entropy)
  const chunks = `${entropyBits}${checksumBits}`.match(/(.{1,11})/g)
  if (!chunks) {
    throw new Error('InvalidVarSeedLength')
  }
  return chunks.map(chunk => BIP39_WORDLIST[binaryToByte(chunk)]).join(' ')
}

async function mnemonicWordsToEntropy(mnemonic: string): Promise<Uint8Array> {
  const words = mnemonic.trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (words.length === 0 || words.length % 3 !== 0) {
    throw new Error('InvalidVarSeedPhrase')
  }
  const bits = words
    .map(word => {
      const index = BIP39_WORDLIST.indexOf(word)
      if (index === -1) {
        throw new Error('InvalidVarSeedPhrase')
      }
      return lpad(index.toString(2), '0', 11)
    })
    .join('')
  const dividerIndex = Math.floor(bits.length / 33) * 32
  const entropyBits = bits.slice(0, dividerIndex)
  const checksumBits = bits.slice(dividerIndex)
  const groups = entropyBits.match(/(.{1,8})/g)
  if (!groups) {
    throw new Error('InvalidVarSeedPhrase')
  }
  const entropy = Uint8Array.from(groups.map(binaryToByte))
  if (entropy.length !== 32) {
    throw new Error('InvalidVarSeedLength')
  }
  const expectedChecksum = await deriveChecksumBits(entropy)
  if (expectedChecksum !== checksumBits) {
    throw new Error('InvalidVarSeedPhrase')
  }
  return entropy
}

function getMasterSeedStorageKey(did: string): string {
  return `${MASTER_SEED_PREFIX}${did}`
}

function getUserPrivateStorageKey(did: string): string {
  return `${USER_PRIVATE_KEY_PREFIX}${did}`
}

function getUserPublicStorageKey(did: string): string {
  return `${USER_PUBLIC_KEY_PREFIX}${did}`
}

function getVerifierPrivateStorageKey(did: string): string {
  return `${VERIFIER_PRIVATE_KEY_PREFIX}${did}`
}

function getVerifierPublicStorageKey(did: string): string {
  return `${VERIFIER_PUBLIC_KEY_PREFIX}${did}`
}

export function getStoredVarMasterSeedBase64(did: string): string | null {
  return localStorage.getItem(getMasterSeedStorageKey(did))
}

export async function formatVarSeedForExport(
  seedBase64: string,
): Promise<string> {
  const entropy = fromBase64(seedBase64)
  return entropyToMnemonicWords(entropy)
}

async function parseVarSeedImport(value: string): Promise<string> {
  const entropy = await mnemonicWordsToEntropy(value)
  return toBase64(entropy)
}

export async function exportVarMasterSeed(did: string): Promise<string | null> {
  const seedBase64 = getStoredVarMasterSeedBase64(did)
  if (!seedBase64) return null
  return formatVarSeedForExport(seedBase64)
}

export function ensureVarMasterSeed(did: string): Promise<string> {
  const existing = getStoredVarMasterSeedBase64(did)
  if (existing) {
    const decoded = fromBase64(existing)
    if (decoded.length === 32) {
      return Promise.resolve(existing)
    }
  }

  const hadLegacyKeys = Boolean(
    localStorage.getItem(getUserPrivateStorageKey(did)) ||
      localStorage.getItem(getUserPublicStorageKey(did)) ||
      localStorage.getItem(getVerifierPrivateStorageKey(did)) ||
      localStorage.getItem(getVerifierPublicStorageKey(did)),
  )

  const seed = crypto.getRandomValues(new Uint8Array(32))
  const seedBase64 = toBase64(seed)
  localStorage.setItem(getMasterSeedStorageKey(did), seedBase64)
  if (hadLegacyKeys) {
    logger.warn(
      'var keyring: rotating legacy keys to master-seed-derived keys',
      {
        did,
      },
    )
  }
  return Promise.resolve(seedBase64)
}

export async function ensureVarDerivedKeyMaterial(
  did: string,
): Promise<VarDerivedKeyMaterial> {
  const masterSeedBase64 = await ensureVarMasterSeed(did)
  const masterSeed = fromBase64(masterSeedBase64)
  if (masterSeed.length !== 32) {
    throw new Error('InvalidVarMasterSeedLength')
  }

  const [userSeed, verifierSeed] = await Promise.all([
    deriveSubSeed(masterSeed, USER_KEY_INFO),
    deriveSubSeed(masterSeed, VERIFIER_KEY_INFO),
  ])

  const sodium = await loadSodium()
  await sodium.ready

  const userKeypair = sodium.crypto_box_seed_keypair(userSeed)
  const verifierKeypair = sodium.crypto_sign_seed_keypair(verifierSeed)

  const material: VarDerivedKeyMaterial = {
    masterSeedBase64,
    userPrivateKeyPkcs8Base64: toBase64(
      concatBytes(X25519_PKCS8_PREFIX_DER, userKeypair.privateKey),
    ),
    userPublicKeySpkiBase64: toBase64(
      concatBytes(X25519_SPKI_PREFIX_DER, userKeypair.publicKey),
    ),
    verifierPrivateKeyPkcs8Base64: toBase64(
      concatBytes(ED25519_PKCS8_PREFIX_DER, verifierSeed),
    ),
    verifierPublicKeyBase64: toBase64(verifierKeypair.publicKey),
  }

  localStorage.setItem(
    getUserPrivateStorageKey(did),
    material.userPrivateKeyPkcs8Base64,
  )
  localStorage.setItem(
    getUserPublicStorageKey(did),
    material.userPublicKeySpkiBase64,
  )
  localStorage.setItem(
    getVerifierPrivateStorageKey(did),
    material.verifierPrivateKeyPkcs8Base64,
  )
  localStorage.setItem(
    getVerifierPublicStorageKey(did),
    material.verifierPublicKeyBase64,
  )

  return material
}

export async function importVarMasterSeed(
  did: string,
  value: string,
): Promise<VarDerivedKeyMaterial> {
  const seedBase64 = await parseVarSeedImport(value)
  localStorage.setItem(getMasterSeedStorageKey(did), seedBase64)
  return ensureVarDerivedKeyMaterial(did)
}
