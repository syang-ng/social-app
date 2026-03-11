export type VarDerivedKeyMaterial = {
  masterSeedBase64: string
  userPrivateKeyPkcs8Base64: string
  userPublicKeySpkiBase64: string
  verifierPrivateKeyPkcs8Base64: string
  verifierPublicKeyBase64: string
}

export function getStoredVarMasterSeedBase64(_did: string): string | null {
  return null
}

export function formatVarSeedForExport(seedBase64: string): Promise<string> {
  return Promise.resolve(seedBase64)
}

export function exportVarMasterSeed(_did: string): Promise<string | null> {
  return Promise.resolve(null)
}

export function ensureVarMasterSeed(_did: string): Promise<string> {
  return Promise.reject(
    new Error('ensureVarMasterSeed is only implemented on web'),
  )
}

export function ensureVarDerivedKeyMaterial(
  _did: string,
): Promise<VarDerivedKeyMaterial> {
  return Promise.reject(
    new Error('ensureVarDerivedKeyMaterial is only implemented on web'),
  )
}

export function importVarMasterSeed(
  _did: string,
  _value: string,
): Promise<VarDerivedKeyMaterial> {
  return Promise.reject(
    new Error('importVarMasterSeed is only implemented on web'),
  )
}
