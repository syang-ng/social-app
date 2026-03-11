import {useCallback, useEffect, useMemo, useState} from 'react'
import {ActivityIndicator, Modal, View} from 'react-native'
import {AppBskyFeedPost} from '@atproto/api'
import {msg} from '@lingui/core/macro'
import {useLingui} from '@lingui/react'
import {Trans} from '@lingui/react/macro'
import {useFocusEffect} from '@react-navigation/native'
import {useInfiniteQuery, useQuery} from '@tanstack/react-query'

import {
  type CommonNavigatorParams,
  type NativeStackScreenProps,
} from '#/lib/routes/types'
import {cleanError} from '#/lib/strings/errors'
import {getPromotionServicesForFeed} from '#/lib/var/promotion'
import {
  createPromotionTask,
  getRegisteredUserCount,
  type PromotionTaskSetupStage,
  setupPromotionTaskIssueChain,
} from '#/lib/var/promotion-service'
import {ensureVarVerifierKeypair} from '#/lib/var/verifier-keypair'
import {logger} from '#/logger'
import {usePreferencesQuery} from '#/state/queries/preferences'
import {useAgent} from '#/state/session'
import {useSetMinimalShellMode} from '#/state/shell'
import {atoms as a, useTheme} from '#/alf'
import {Button, ButtonText} from '#/components/Button'
import * as TextField from '#/components/forms/TextField'
import * as Layout from '#/components/Layout'
import {Text} from '#/components/Typography'

type Props = NativeStackScreenProps<CommonNavigatorParams, 'NewPromotion'>

type OwnPostItem = {
  uri: string
  text: string
  createdAt?: string
}

type PromotionServiceEntry = {
  feedUri: string
  serviceUrl: string
  recordUri: string
  repoDid: string
}

type PublishStepId =
  | 'task-creation'
  | 'user-key-load'
  | 'issue-token'
  | 'upload-public-params'
  | 'update-task'
  | 'upload-bundle-seed'
  | 'encrypt'
  | 'import-receipts'

type PublishStepState = Record<PublishStepId, 'pending' | 'running' | 'done'>

const PUBLISH_STEP_ORDER: PublishStepId[] = [
  'task-creation',
  'user-key-load',
  'issue-token',
  'upload-public-params',
  'update-task',
  'upload-bundle-seed',
  'encrypt',
  'import-receipts',
]

const EMPTY_PUBLISH_STEP_STATE: PublishStepState = {
  'task-creation': 'pending',
  'user-key-load': 'pending',
  'issue-token': 'pending',
  'upload-public-params': 'pending',
  'update-task': 'pending',
  'upload-bundle-seed': 'pending',
  encrypt: 'pending',
  'import-receipts': 'pending',
}

const PUBLISH_STEP_LABELS: Record<PublishStepId, string> = {
  'task-creation': 'Task creation',
  'user-key-load': 'User key load',
  'issue-token': 'Issue token',
  'upload-public-params': 'Upload public params',
  'update-task': 'Update task ppHash',
  'upload-bundle-seed': 'Upload encrypted bundle seed',
  encrypt: 'Encrypt receipts',
  'import-receipts': 'Import encrypted receipts',
}

function getPostText(postRecord: unknown): string {
  if (AppBskyFeedPost.isRecord(postRecord)) {
    const record = postRecord as Record<string, unknown>
    return typeof record.text === 'string' ? record.text : ''
  }
  return ''
}

function parsePositiveInt(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10)
  if (!Number.isFinite(parsed) || parsed < 1) return fallback
  return parsed
}

export function NewPromotionScreen({}: Props) {
  const {_} = useLingui()
  const t = useTheme()
  const setMinimalShellMode = useSetMinimalShellMode()
  const agent = useAgent()
  const {data: preferences} = usePreferencesQuery()
  const [selectedServiceKey, setSelectedServiceKey] = useState<string | null>(
    null,
  )
  const [selectedPostUris, setSelectedPostUris] = useState<Set<string>>(
    () => new Set(),
  )
  const [submitResult, setSubmitResult] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [verifierPublicKeyBase64, setVerifierPublicKeyBase64] = useState('')
  const [auditLimit, setAuditLimit] = useState('1')
  const [targetViews, setTargetViews] = useState('10000')
  const [campaignName, setCampaignName] = useState('')
  const [progressVisible, setProgressVisible] = useState(false)
  const [progressPostUri, setProgressPostUri] = useState<string | null>(null)
  const [publishStepState, setPublishStepState] = useState<PublishStepState>(
    EMPTY_PUBLISH_STEP_STATE,
  )

  const markStep = useCallback(
    (step: PublishStepId, status: PublishStepState[PublishStepId]) => {
      setPublishStepState(prev => ({
        ...prev,
        [step]: status,
      }))
    },
    [],
  )

  const onSetupStage = useCallback(
    (stage: PromotionTaskSetupStage) => {
      if (stage === 'user-key-load-start') markStep('user-key-load', 'running')
      if (stage === 'user-key-load-done') markStep('user-key-load', 'done')
      if (stage === 'issue-token-start') markStep('issue-token', 'running')
      if (stage === 'issue-token-done') markStep('issue-token', 'done')
      if (stage === 'upload-public-params-start') {
        markStep('upload-public-params', 'running')
      }
      if (stage === 'upload-public-params-done') {
        markStep('upload-public-params', 'done')
      }
      if (stage === 'update-task-start') markStep('update-task', 'running')
      if (stage === 'update-task-done') markStep('update-task', 'done')
      if (stage === 'upload-bundle-seed-start') {
        markStep('upload-bundle-seed', 'running')
      }
      if (stage === 'upload-bundle-seed-done') {
        markStep('upload-bundle-seed', 'done')
      }
      if (stage === 'encrypt-start') markStep('encrypt', 'running')
      if (stage === 'encrypt-done') markStep('encrypt', 'done')
      if (stage === 'import-receipts-start') {
        markStep('import-receipts', 'running')
      }
      if (stage === 'import-receipts-done') markStep('import-receipts', 'done')
    },
    [markStep],
  )

  const verifierKeyQuery = useQuery({
    queryKey: ['var-verifier-public-key', agent.session?.did],
    enabled: Boolean(agent.session?.did),
    staleTime: Infinity,
    queryFn: async () => ensureVarVerifierKeypair(agent),
  })

  useFocusEffect(
    useCallback(() => {
      setMinimalShellMode(false)
    }, [setMinimalShellMode]),
  )

  const serviceQuery = useQuery({
    queryKey: [
      'promotion-new-services',
      preferences?.savedFeeds,
      agent.session?.did,
    ],
    enabled: Boolean(agent.session?.did),
    staleTime: 1000 * 60,
    queryFn: async (): Promise<PromotionServiceEntry[]> => {
      const feedUris = Array.from(
        new Set(
          (preferences?.savedFeeds || [])
            .filter(feed => feed.type === 'feed')
            .map(feed => feed.value)
            .filter(value => value.includes('app.bsky.feed.generator')),
        ),
      )

      const resolved = await Promise.all(
        feedUris.map(async feedUri => {
          try {
            const services = await getPromotionServicesForFeed({
              agent,
              feedUri,
            })
            return services.map(service => ({
              feedUri,
              serviceUrl: service.serviceEndpoint,
              recordUri: service.recordUri,
              repoDid: service.repoDid,
            }))
          } catch (err) {
            logger.error('new promotion: resolve service failed', {
              feedUri,
              message: err instanceof Error ? err.message : String(err),
            })
            return []
          }
        }),
      )

      const entries = resolved.flat()

      const deduped = new Map<string, PromotionServiceEntry>()
      for (const entry of entries) {
        deduped.set(
          `${entry.feedUri}::${entry.serviceUrl}::${entry.recordUri}`,
          entry,
        )
      }
      return Array.from(deduped.values())
    },
  })

  const serviceEntries = useMemo(
    () => serviceQuery.data || [],
    [serviceQuery.data],
  )
  const registeredCountsQuery = useQuery({
    queryKey: [
      'promotion-registered-counts',
      serviceEntries.map(entry => `${entry.serviceUrl}::${entry.recordUri}`),
    ],
    enabled: serviceEntries.length > 0,
    staleTime: 1000 * 60,
    queryFn: async () => {
      const counts = new Map<string, number | null>()
      const uniqueServiceUrls = Array.from(
        new Set(serviceEntries.map(entry => entry.serviceUrl)),
      )
      await Promise.all(
        uniqueServiceUrls.map(async serviceUrl => {
          try {
            const count = await getRegisteredUserCount({serviceUrl})
            counts.set(serviceUrl, count)
          } catch (err) {
            logger.error('new promotion: load registered user count failed', {
              serviceUrl,
              message: err instanceof Error ? err.message : String(err),
            })
            counts.set(serviceUrl, null)
          }
        }),
      )
      return counts
    },
  })

  useEffect(() => {
    if (!serviceEntries.length) {
      setSelectedServiceKey(null)
      return
    }
    if (!selectedServiceKey) {
      setSelectedServiceKey(
        `${serviceEntries[0].feedUri}::${serviceEntries[0].serviceUrl}::${serviceEntries[0].recordUri}`,
      )
      return
    }
    const stillExists = serviceEntries.some(
      entry =>
        `${entry.feedUri}::${entry.serviceUrl}::${entry.recordUri}` ===
        selectedServiceKey,
    )
    if (!stillExists) {
      setSelectedServiceKey(
        `${serviceEntries[0].feedUri}::${serviceEntries[0].serviceUrl}::${serviceEntries[0].recordUri}`,
      )
    }
  }, [selectedServiceKey, serviceEntries])

  useEffect(() => {
    if (!verifierKeyQuery.data) return
    setVerifierPublicKeyBase64(current =>
      current.trim() ? current : verifierKeyQuery.data || '',
    )
  }, [verifierKeyQuery.data])

  const postsQuery = useInfiniteQuery({
    queryKey: ['new-promotion-own-posts', agent.session?.did],
    enabled: Boolean(agent.session?.did),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({pageParam}: {pageParam: string | undefined}) => {
      const did = agent.session?.did
      if (!did) {
        return {cursor: undefined, posts: [] as OwnPostItem[]}
      }
      const res = await agent.getAuthorFeed({
        actor: did,
        filter: 'posts_no_replies',
        limit: 10,
        cursor: pageParam,
      })
      return {
        cursor: res.data.cursor,
        posts: res.data.feed.map(item => ({
          uri: item.post.uri,
          text: getPostText(item.post.record),
          createdAt: item.post.indexedAt,
        })),
      }
    },
    getNextPageParam: lastPage => lastPage.cursor || undefined,
  })

  const posts = useMemo(
    () => postsQuery.data?.pages.flatMap(page => page.posts) || [],
    [postsQuery.data],
  )

  const selectedCount = selectedPostUris.size

  const selectedService = useMemo(() => {
    if (!selectedServiceKey) return null
    return (
      serviceEntries.find(
        entry =>
          `${entry.feedUri}::${entry.serviceUrl}::${entry.recordUri}` ===
          selectedServiceKey,
      ) || null
    )
  }, [selectedServiceKey, serviceEntries])
  const selectedServiceRegisteredCount = useMemo(() => {
    if (!selectedService || !registeredCountsQuery.data) return null
    return registeredCountsQuery.data.get(selectedService.serviceUrl) ?? null
  }, [registeredCountsQuery.data, selectedService])

  const togglePost = useCallback((uri: string) => {
    setSelectedPostUris(prev => {
      const next = new Set(prev)
      if (next.has(uri)) {
        next.delete(uri)
      } else {
        next.add(uri)
      }
      return next
    })
  }, [])

  const onPublish = useCallback(async () => {
    const did = agent.session?.did
    const accessJwt = agent.session?.accessJwt
    if (!did || !selectedService || selectedPostUris.size === 0) return
    if (!verifierPublicKeyBase64.trim()) {
      setSubmitResult('missing verifierPublicKeyBase64')
      return
    }

    setIsSubmitting(true)
    setSubmitResult(null)
    const targets = Array.from(selectedPostUris)
    const parsedAuditLimit = parsePositiveInt(auditLimit, 1)
    const parsedTargetViews = parsePositiveInt(targetViews, 10000)

    try {
      const failures: Array<{postUri: string; reason: string}> = []
      let success = 0

      for (const postUri of targets) {
        setProgressVisible(true)
        setProgressPostUri(postUri)
        setPublishStepState(EMPTY_PUBLISH_STEP_STATE)
        try {
          markStep('task-creation', 'running')
          console.log('new promotion: task creation start', {
            postUri,
            serviceUrl: selectedService.serviceUrl,
            feedUri: selectedService.feedUri,
          })
          const created = await createPromotionTask({
            serviceUrl: selectedService.serviceUrl,
            accessJwt,
            payload: {
              postUri,
              feedUri: selectedService.feedUri,
              creatorDid: did,
              verifierPublicKeyBase64: verifierPublicKeyBase64.trim(),
              auditLimit: parsedAuditLimit,
              targetViews: parsedTargetViews,
              metadata: {
                source: 'app-manual-selection',
                ...(campaignName.trim()
                  ? {campaignName: campaignName.trim()}
                  : {}),
              },
            },
          })
          markStep('task-creation', 'done')
          console.log('new promotion: task creation done', {
            postUri,
            taskId: created.taskId,
            serviceUrl: selectedService.serviceUrl,
          })

          await setupPromotionTaskIssueChain({
            serviceUrl: selectedService.serviceUrl,
            creatorDid: did,
            taskId: created.taskId,
            verifierDid: did,
            expectedVerifierPublicKeyBase64: verifierPublicKeyBase64.trim(),
            accessJwt,
            onStage: onSetupStage,
          })
          console.log('new promotion: issue/encrypt/import done', {
            postUri,
            taskId: created.taskId,
            serviceUrl: selectedService.serviceUrl,
          })
          success++
        } catch (err) {
          const reason = cleanError(err)
          failures.push({postUri, reason})
          console.error('new promotion: publish failed', {
            postUri,
            reason,
          })
        }
      }

      const failed = failures.length
      if (failed > 0) {
        const first = failures[0]
        setSubmitResult(
          `published ${success}, failed ${failed}. first error: ${first.postUri} -> ${first.reason}`,
        )
      } else {
        setSubmitResult(`published ${success}, failed 0`)
      }
      if (success > 0) {
        setSelectedPostUris(new Set())
      }
    } catch (err) {
      setSubmitResult(cleanError(err))
    } finally {
      setProgressVisible(false)
      setProgressPostUri(null)
      setIsSubmitting(false)
    }
  }, [
    agent.session?.accessJwt,
    agent.session?.did,
    auditLimit,
    campaignName,
    selectedPostUris,
    selectedService,
    targetViews,
    verifierPublicKeyBase64,
    markStep,
    onSetupStage,
  ])

  const doneStepCount = useMemo(
    () =>
      PUBLISH_STEP_ORDER.filter(step => publishStepState[step] === 'done')
        .length,
    [publishStepState],
  )
  const progressPct = Math.round(
    (doneStepCount / Math.max(1, PUBLISH_STEP_ORDER.length)) * 100,
  )

  return (
    <Layout.Screen testID="newPromotionScreen">
      <Layout.Header.Outer>
        <Layout.Header.BackButton />
        <Layout.Header.Content align="left">
          <Layout.Header.TitleText>
            <Trans>New Promotion</Trans>
          </Layout.Header.TitleText>
        </Layout.Header.Content>
        <Layout.Header.Slot />
      </Layout.Header.Outer>

      <Layout.Content>
        <Modal transparent visible={progressVisible} animationType="fade">
          <View
            style={[
              a.flex_1,
              a.align_center,
              a.justify_center,
              {backgroundColor: 'rgba(0,0,0,0.35)'},
            ]}>
            <View
              style={[
                a.w_full,
                a.mx_lg,
                a.p_lg,
                a.rounded_md,
                t.atoms.bg,
                a.gap_md,
              ]}>
              <Text style={[a.font_bold]}>
                <Trans>Publishing promotion</Trans>
              </Text>
              {progressPostUri ? (
                <Text numberOfLines={1} style={[t.atoms.text_contrast_medium]}>
                  {progressPostUri}
                </Text>
              ) : null}
              <View
                style={[
                  a.rounded_full,
                  t.atoms.bg_contrast_25,
                  {height: 8, overflow: 'hidden'},
                ]}>
                <View
                  style={[
                    a.h_full,
                    {
                      width: `${progressPct}%`,
                      backgroundColor: t.palette.primary_500,
                    },
                  ]}
                />
              </View>
              <Text style={[t.atoms.text_contrast_medium]}>{progressPct}%</Text>
              <View style={[a.gap_xs]}>
                {PUBLISH_STEP_ORDER.map(step => (
                  <Text key={step} style={[t.atoms.text_contrast_medium]}>
                    {publishStepState[step] === 'done'
                      ? '✓'
                      : publishStepState[step] === 'running'
                        ? '…'
                        : '○'}{' '}
                    {PUBLISH_STEP_LABELS[step]}
                  </Text>
                ))}
              </View>
              <ActivityIndicator />
            </View>
          </View>
        </Modal>

        <View style={[a.p_lg, a.gap_md]}>
          <View style={[a.gap_sm]}>
            <Text style={[a.font_bold]}>
              <Trans>Select promotion feed</Trans>
            </Text>
            {serviceQuery.isPending ? (
              <ActivityIndicator />
            ) : serviceEntries.length === 0 ? (
              <Text style={[t.atoms.text_contrast_medium]}>
                <Trans>
                  No promotion-enabled feed services found in your saved feeds.
                </Trans>
              </Text>
            ) : (
              <View style={[a.gap_xs]}>
                {serviceEntries.map(entry => {
                  const key = `${entry.feedUri}::${entry.serviceUrl}::${entry.recordUri}`
                  const selected = key === selectedServiceKey
                  return (
                    <Button
                      key={key}
                      label={`${entry.feedUri} ${selected ? '(selected)' : ''}`}
                      onPress={() => setSelectedServiceKey(key)}
                      size="small"
                      color={selected ? 'primary' : 'secondary'}
                      variant={selected ? 'solid' : 'outline'}>
                      <ButtonText numberOfLines={1}>
                        {entry.feedUri} - {entry.serviceUrl}
                      </ButtonText>
                    </Button>
                  )
                })}
              </View>
            )}
            {selectedService ? (
              <Text style={[t.atoms.text_contrast_medium]}>
                <Trans>
                  Registered users for this provider:{' '}
                  {selectedServiceRegisteredCount ?? 'unknown'}
                </Trans>
              </Text>
            ) : null}
          </View>

          <View style={[a.flex_row, a.align_center, a.justify_between]}>
            <Text style={[a.font_bold]}>
              <Trans>Your Posts (10 per page)</Trans>
            </Text>
            <Button
              label={_(msg`Publish promotion tasks`)}
              size="small"
              color="primary"
              variant="solid"
              disabled={
                isSubmitting || !selectedService || selectedPostUris.size === 0
              }
              onPress={() => {
                void onPublish()
              }}>
              <ButtonText>
                <Trans>Publish ({selectedCount})</Trans>
              </ButtonText>
            </Button>
          </View>

          <View style={[a.gap_sm]}>
            <Text style={[a.font_bold]}>
              <Trans>Task Settings</Trans>
            </Text>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>
                Audit Information will be collected for the promoted posts.
              </Trans>
            </Text>
            <View style={[a.flex_row, a.gap_sm]}>
              <View style={[a.flex_1]}>
                <TextField.Root>
                  <TextField.Input
                    label={_(msg`Audit limit`)}
                    value={auditLimit}
                    onChangeText={setAuditLimit}
                    keyboardType="number-pad"
                    inputMode="numeric"
                    placeholder={_(msg`1`)}
                  />
                </TextField.Root>
                <Text style={[a.text_xs, t.atoms.text_contrast_medium]}>
                  <Trans>Number of audit attempts.</Trans>
                </Text>
              </View>
              <View style={[a.flex_1]}>
                <TextField.Root>
                  <TextField.Input
                    label={_(msg`Target views`)}
                    value={targetViews}
                    onChangeText={setTargetViews}
                    keyboardType="number-pad"
                    inputMode="numeric"
                    placeholder={_(msg`10000`)}
                  />
                </TextField.Root>
                <Text style={[a.text_xs, t.atoms.text_contrast_medium]}>
                  <Trans>Expected delivery goal for this task.</Trans>
                </Text>
              </View>
            </View>
            <TextField.Root>
              <TextField.Input
                label={_(msg`Campaign name`)}
                value={campaignName}
                onChangeText={setCampaignName}
                placeholder={_(msg`Optional campaign name`)}
              />
            </TextField.Root>
          </View>

          {submitResult ? (
            <Text style={[t.atoms.text_contrast_medium]}>{submitResult}</Text>
          ) : null}

          {postsQuery.isPending ? (
            <ActivityIndicator />
          ) : posts.length === 0 ? (
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>No posts found.</Trans>
            </Text>
          ) : (
            <View style={[a.gap_sm]}>
              {posts.map(post => {
                const selected = selectedPostUris.has(post.uri)
                return (
                  <View
                    key={post.uri}
                    style={[
                      a.rounded_md,
                      a.border,
                      t.atoms.border_contrast_low,
                      a.p_md,
                      a.gap_sm,
                    ]}>
                    <Text numberOfLines={3}>
                      {post.text || _(msg`(No text content)`)}
                    </Text>
                    <Text
                      numberOfLines={1}
                      style={[a.text_xs, t.atoms.text_contrast_medium]}>
                      {post.uri}
                    </Text>
                    <View style={[a.flex_row, a.justify_end]}>
                      <Button
                        label={
                          selected
                            ? _(msg`Selected for promotion`)
                            : _(msg`Select for promotion`)
                        }
                        size="small"
                        color={selected ? 'primary' : 'secondary'}
                        variant={selected ? 'solid' : 'outline'}
                        onPress={() => togglePost(post.uri)}>
                        <ButtonText>
                          {selected ? (
                            <Trans>Selected</Trans>
                          ) : (
                            <Trans>Select</Trans>
                          )}
                        </ButtonText>
                      </Button>
                    </View>
                  </View>
                )
              })}
            </View>
          )}

          {postsQuery.hasNextPage ? (
            <Button
              label={_(msg`Load 10 more posts`)}
              size="small"
              color="secondary"
              variant="outline"
              disabled={postsQuery.isFetchingNextPage}
              onPress={() => {
                void postsQuery.fetchNextPage()
              }}>
              <ButtonText>
                <Trans>Load 10 more</Trans>
              </ButtonText>
            </Button>
          ) : null}
        </View>
      </Layout.Content>
    </Layout.Screen>
  )
}
