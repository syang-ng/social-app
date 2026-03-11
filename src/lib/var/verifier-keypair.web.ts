import {type AtpAgent} from '@atproto/api'

import {ensureVarDerivedKeyMaterial} from '#/lib/var/keyring'
import {logger} from '#/logger'

export async function ensureVarVerifierKeypair(
  agent: AtpAgent,
): Promise<string | null> {
  try {
    const did = agent.session?.did
    if (!did) return null

    const material = await ensureVarDerivedKeyMaterial(did)
    return material.verifierPublicKeyBase64
  } catch (err) {
    logger.error('verifier keypair: failed to initialize local keypair', {
      message: err instanceof Error ? err.message : String(err),
    })
    return null
  }
}
