import {
  AtUri,
  BskyAgent as AtprotoBskyAgent,
  type BskyAgent,
} from '@atproto/api'

import {logger} from '#/logger'

export const PROMOTION_SERVICE_COLLECTION =
  'com.hackingdecentralized.feed.promotionService'

type DidDocumentService = {
  id?: string
  type?: string
  serviceEndpoint?: string
}

type DidDocument = {
  id?: string
  service?: DidDocumentService | DidDocumentService[]
}

export type PromotionServiceRecord = {
  feedUri: string
  serviceEndpoint: string
  status: 'active' | 'paused' | 'deprecated'
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function toDidHost(uri: AtUri, agent: BskyAgent): Promise<string> {
  if (uri.host.startsWith('did:')) {
    return Promise.resolve(uri.host)
  }
  return agent.resolveHandle({handle: uri.host}).then(res => res.data.did)
}

async function fetchDidDocument(did: string): Promise<DidDocument | null> {
  try {
    if (did.startsWith('did:plc:')) {
      const res = await fetch(
        `https://plc.directory/${encodeURIComponent(did)}`,
      )
      if (!res.ok) return null
      return (await res.json()) as DidDocument
    }
    if (did.startsWith('did:web:')) {
      const host = did.replace(/^did:web:/, '')
      const res = await fetch(`https://${host}/.well-known/did.json`)
      if (!res.ok) return null
      return (await res.json()) as DidDocument
    }
    return null
  } catch {
    return null
  }
}

function extractPdsEndpointFromDidDocument(
  did: string,
  doc: DidDocument | null,
): string | null {
  if (!doc || !doc.service) return null
  const services = Array.isArray(doc.service) ? doc.service : [doc.service]
  const pdsService = services.find(service => {
    const serviceIdMatches =
      service.id === '#atproto_pds' || service.id === `${did}#atproto_pds`
    const serviceTypeMatches = service.type === 'AtprotoPersonalDataServer'
    return serviceIdMatches || serviceTypeMatches
  })
  if (typeof pdsService?.serviceEndpoint !== 'string') return null
  return pdsService.serviceEndpoint
}

async function createRepoPdsAgent({
  did,
  fallbackAgent,
}: {
  did: string
  fallbackAgent: BskyAgent
}): Promise<BskyAgent> {
  const didDoc = await fetchDidDocument(did)
  const pdsEndpoint = extractPdsEndpointFromDidDocument(did, didDoc)
  if (!pdsEndpoint) {
    logger.debug('promotion service lookup: missing repo pds endpoint', {did})
    return fallbackAgent
  }
  logger.debug('promotion service lookup: using repo pds endpoint', {
    did,
    pdsEndpoint,
  })
  return new AtprotoBskyAgent({service: pdsEndpoint})
}

function normalizeAtUri(value: string): string {
  try {
    return new AtUri(value).toString()
  } catch {
    return value
  }
}

export function toPromotionServiceRecord(
  value: unknown,
): PromotionServiceRecord | null {
  if (!isObject(value)) return null
  const feedUri = value.feedUri
  const serviceEndpoint = value.serviceEndpoint
  const status = value.status
  if (
    typeof feedUri !== 'string' ||
    typeof serviceEndpoint !== 'string' ||
    (status !== 'active' && status !== 'paused' && status !== 'deprecated')
  ) {
    return null
  }
  return {
    feedUri,
    serviceEndpoint,
    status,
  }
}

export async function getPromotionServiceEndpointForFeed({
  agent,
  feedUri,
}: {
  agent: BskyAgent
  feedUri: string
}): Promise<string | null> {
  const normalizedFeedUri = normalizeAtUri(feedUri)
  let urip: AtUri
  try {
    urip = new AtUri(normalizedFeedUri)
  } catch (err) {
    logger.debug('promotion service lookup: invalid feed URI', {
      feedUri,
      message: err instanceof Error ? err.message : String(err),
    })
    return null
  }
  if (urip.collection !== 'app.bsky.feed.generator') {
    logger.debug('promotion service lookup: not a feed-generator URI', {
      feedUri: normalizedFeedUri,
      collection: urip.collection,
    })
    return null
  }
  const repoDid = await toDidHost(urip, agent)
  const repoPdsAgent = await createRepoPdsAgent({
    did: repoDid,
    fallbackAgent: agent,
  })
  let cursor: string | undefined
  let totalScanned = 0
  let invalidRecords = 0
  let feedUriMismatches = 0
  let nonActiveMatches = 0
  let invalidEndpointMatches = 0

  logger.debug('promotion service lookup: start', {
    feedUri,
    repoDid,
  })

  do {
    const {data} = await repoPdsAgent.api.com.atproto.repo.listRecords({
      repo: repoDid,
      collection: PROMOTION_SERVICE_COLLECTION,
      limit: 100,
      cursor,
    })
    logger.debug('promotion service lookup: fetched page', {
      repoDid,
      feedUri: normalizedFeedUri,
      recordCount: data.records.length,
      cursor: cursor ?? null,
      nextCursor: data.cursor ?? null,
    })

    for (const record of data.records) {
      totalScanned++
      const promotion = toPromotionServiceRecord(record.value)
      if (!promotion) {
        invalidRecords++
        continue
      }
      const normalizedRecordFeedUri = normalizeAtUri(promotion.feedUri)
      if (normalizedRecordFeedUri !== normalizedFeedUri) {
        feedUriMismatches++
        continue
      }
      if (promotion.status !== 'active') {
        nonActiveMatches++
        // Keep scanning in case there are multiple declarations and a later one is active.
        continue
      }
      if (!/^https:\/\//i.test(promotion.serviceEndpoint)) {
        invalidEndpointMatches++
        // Keep scanning in case another declaration has a valid endpoint.
        continue
      }

      logger.debug('promotion service lookup: matched', {
        feedUri: normalizedFeedUri,
        repoDid,
        recordUri: record.uri,
        serviceEndpoint: promotion.serviceEndpoint,
      })
      return promotion.serviceEndpoint
    }

    cursor = data.cursor
  } while (cursor)

  logger.debug('promotion service lookup: no match', {
    feedUri: normalizedFeedUri,
    repoDid,
    totalScanned,
    invalidRecords,
    feedUriMismatches,
    nonActiveMatches,
    invalidEndpointMatches,
  })

  return null
}

export function parsePromotionFromFeedContext(
  feedContext: string | undefined,
): boolean {
  if (!feedContext) return false
  try {
    const parsed = JSON.parse(feedContext)
    return isObject(parsed) && parsed.promotion === true
  } catch {
    return false
  }
}

export function parseTaskIdFromFeedContext(
  feedContext: string | undefined,
): string | null {
  if (!feedContext) return null
  try {
    const parsed = JSON.parse(feedContext) as Record<string, unknown>
    const direct =
      (typeof parsed.taskId === 'string' && parsed.taskId) ||
      (typeof parsed.task_id === 'string' && parsed.task_id) ||
      null
    if (direct) return direct

    const promotion = parsed.promotion
    if (typeof promotion === 'object' && promotion !== null) {
      const nested = promotion as Record<string, unknown>
      if (typeof nested.taskId === 'string') return nested.taskId
      if (typeof nested.task_id === 'string') return nested.task_id
    }
    return null
  } catch {
    return null
  }
}

export function parsePromotionViewsResponse(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.floor(value))
  }
  if (!isObject(value)) return null

  const candidates = [
    value.views,
    value.viewCount,
    value.count,
    value.totalViews,
  ]

  for (const candidate of candidates) {
    if (typeof candidate === 'number' && Number.isFinite(candidate)) {
      return Math.max(0, Math.floor(candidate))
    }
    if (typeof candidate === 'string') {
      const parsed = Number(candidate)
      if (Number.isFinite(parsed)) {
        return Math.max(0, Math.floor(parsed))
      }
    }
  }
  return null
}
