import {useCallback, useMemo, useState} from 'react'
import {ActivityIndicator, Modal, ScrollView, View} from 'react-native'
import {AtUri} from '@atproto/api'
import {msg} from '@lingui/core/macro'
import {useLingui} from '@lingui/react'
import {Trans} from '@lingui/react/macro'
import {useFocusEffect} from '@react-navigation/native'
import {useQuery} from '@tanstack/react-query'

import {
  type CommonNavigatorParams,
  type NativeStackScreenProps,
} from '#/lib/routes/types'
import {getPromotionServicesForFeed} from '#/lib/var/promotion'
import {
  getPromotionPostViews,
  getPromotionTaskAuditMaterial,
  getPromotionTaskProofJson,
  getPromotionTaskValidationState,
  listPromotionTasks,
  type PromotionTask,
  type PromotionTaskProofJson,
  validatePromotionTaskProof,
} from '#/lib/var/promotion-service'
import {logger} from '#/logger'
import {usePreferencesQuery} from '#/state/queries/preferences'
import {useAgent} from '#/state/session'
import {useSetMinimalShellMode} from '#/state/shell'
import {atoms as a, useBreakpoints, useTheme} from '#/alf'
import {Button, ButtonIcon, ButtonText} from '#/components/Button'
import {PlusLarge_Stroke2_Corner0_Rounded as PlusIcon} from '#/components/icons/Plus'
import {SettingsGear2_Stroke2_Corner0_Rounded as SettingsIcon} from '#/components/icons/SettingsGear2'
import {ShieldCheck_Stroke2_Corner0_Rounded as ShieldCheckIcon} from '#/components/icons/Shield'
import * as Layout from '#/components/Layout'
import {Link} from '#/components/Link'
import {Text} from '#/components/Typography'

type Props = NativeStackScreenProps<CommonNavigatorParams, 'Promotion'>

type PromotionTaskWithSource = PromotionTask & {
  serviceUrl: string
}

export function PromotionScreen({navigation}: Props) {
  const {_} = useLingui()
  const t = useTheme()
  const {gtMobile} = useBreakpoints()
  const setMinimalShellMode = useSetMinimalShellMode()
  const agent = useAgent()
  const {data: preferences} = usePreferencesQuery()
  const [validatingTaskKey, setValidatingTaskKey] = useState<string | null>(
    null,
  )
  const [proofViewer, setProofViewer] = useState<{
    visible: boolean
    loading: boolean
    taskId?: string
    data?: PromotionTaskProofJson
    error?: string
  }>({
    visible: false,
    loading: false,
  })

  useFocusEffect(
    useCallback(() => {
      setMinimalShellMode(false)
    }, [setMinimalShellMode]),
  )

  const feedUris = useMemo(
    () =>
      Array.from(
        new Set(
          (preferences?.savedFeeds || [])
            .filter(feed => feed.type === 'feed')
            .map(feed => feed.value)
            .filter(value => value.includes('app.bsky.feed.generator')),
        ),
      ),
    [preferences?.savedFeeds],
  )

  const tasksQuery = useQuery({
    queryKey: ['promotion-tasks-screen', agent.session?.did, feedUris],
    enabled: Boolean(agent.session?.did && feedUris.length > 0),
    staleTime: 1000 * 30,
    queryFn: async () => {
      const did = agent.session?.did
      if (!did) {
        return [] as PromotionTaskWithSource[]
      }

      const endpointByFeed = await Promise.all(
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
            }))
          } catch (err) {
            logger.error(
              'promotion screen: failed resolving service endpoint',
              {
                feedUri,
                message: err instanceof Error ? err.message : String(err),
              },
            )
            return []
          }
        }),
      )

      const serviceUrls = Array.from(
        new Set(endpointByFeed.flat().map(entry => entry.serviceUrl)),
      )

      const accessJwt = agent.session?.accessJwt
      const taskPages = await Promise.all(
        serviceUrls.map(async serviceUrl => {
          try {
            const page = await listPromotionTasks({
              serviceUrl,
              creatorDid: did,
              accessJwt,
            })
            return page.tasks.map(task => ({...task, serviceUrl}))
          } catch (err) {
            logger.error('promotion screen: failed listing tasks', {
              serviceUrl,
              message: err instanceof Error ? err.message : String(err),
            })
            return [] as PromotionTaskWithSource[]
          }
        }),
      )

      const merged = taskPages.flat()
      const dedupedById = new Map<string, PromotionTaskWithSource>()
      for (const task of merged) {
        if (typeof task.taskId !== 'string' || !task.taskId) continue
        const dedupeKey = `${task.serviceUrl}::${task.taskId}`
        dedupedById.set(dedupeKey, task)
      }

      return Array.from(dedupedById.values()).sort((a, b) =>
        String(b.createdAt || '').localeCompare(String(a.createdAt || '')),
      )
    },
  })

  const tasks = tasksQuery.data || []
  const viewsQuery = useQuery({
    queryKey: [
      'promotion-task-views',
      tasks.map(task => `${task.serviceUrl}::${String(task.postUri || '')}`),
    ],
    enabled: tasks.length > 0,
    staleTime: 1000 * 30,
    queryFn: async () => {
      const keyToViews = new Map<string, number>()
      const targets = Array.from(
        new Set(
          tasks
            .filter(
              task =>
                typeof task.postUri === 'string' &&
                task.postUri &&
                typeof task.serviceUrl === 'string' &&
                task.serviceUrl,
            )
            .map(task => `${task.serviceUrl}::${task.postUri as string}`),
        ),
      )
      await Promise.all(
        targets.map(async key => {
          const [serviceUrl, postUri] = key.split('::')
          try {
            const views = await getPromotionPostViews({serviceUrl, postUri})
            keyToViews.set(key, views.viewCount)
          } catch (err) {
            logger.error('promotion screen: failed loading views', {
              serviceUrl,
              postUri,
              message: err instanceof Error ? err.message : String(err),
            })
          }
        }),
      )
      return keyToViews
    },
  })

  const validationStateQuery = useQuery({
    queryKey: [
      'promotion-task-validation-state',
      agent.session?.did,
      tasks.map(task => `${task.serviceUrl}::${task.taskId}`),
    ],
    enabled: Boolean(agent.session?.did) && tasks.length > 0,
    staleTime: Infinity,
    queryFn: () => {
      const ownerDid = agent.session?.did
      const map = new Map<
        string,
        {
          hasAudit: boolean
          count: number
          lastValidatedAt?: string
        }
      >()
      if (!ownerDid) return map
      for (const task of tasks) {
        const key = `${task.serviceUrl}::${task.taskId}`
        const audit = getPromotionTaskAuditMaterial({
          ownerDid,
          taskId: task.taskId,
        })
        const validation = getPromotionTaskValidationState({
          ownerDid,
          taskId: task.taskId,
        })
        map.set(key, {
          hasAudit: Boolean(audit),
          count: validation.count,
          lastValidatedAt: validation.lastValidatedAt,
        })
      }
      return map
    },
  })

  const onValidateTask = useCallback(
    async (task: PromotionTaskWithSource) => {
      const ownerDid = agent.session?.did
      if (!ownerDid) return
      const taskKey = `${task.serviceUrl}::${task.taskId}`
      try {
        setValidatingTaskKey(taskKey)
        console.log('promotion validate: start', {
          taskId: task.taskId,
          serviceUrl: task.serviceUrl,
        })
        const result = await validatePromotionTaskProof({
          serviceUrl: task.serviceUrl,
          ownerDid,
          taskId: task.taskId,
        })
        console.log('promotion validate: done', {
          taskId: task.taskId,
          validationCount: result.validationCount,
          proofEpoch: result.proof.epoch,
          verifiedCount: result.verifyOut.count,
        })
        await validationStateQuery.refetch()
      } catch (err) {
        console.error('promotion validate: failed', {
          taskId: task.taskId,
          serviceUrl: task.serviceUrl,
          message: err instanceof Error ? err.message : String(err),
        })
      } finally {
        setValidatingTaskKey(null)
      }
    },
    [agent.session?.did, validationStateQuery],
  )

  const onViewPost = useCallback(
    (postUri: string) => {
      try {
        const urip = new AtUri(postUri)
        navigation.push('PostThread', {
          name: urip.host,
          rkey: urip.rkey,
        })
      } catch (err) {
        console.error('promotion view post: failed', {
          postUri,
          message: err instanceof Error ? err.message : String(err),
        })
      }
    },
    [navigation],
  )

  const onViewProof = useCallback(async (task: PromotionTaskWithSource) => {
    setProofViewer({
      visible: true,
      loading: true,
      taskId: task.taskId,
    })
    try {
      const proofJson = await getPromotionTaskProofJson({
        serviceUrl: task.serviceUrl,
        taskId: task.taskId,
      })
      setProofViewer({
        visible: true,
        loading: false,
        taskId: task.taskId,
        data: proofJson,
      })
    } catch (err) {
      setProofViewer({
        visible: true,
        loading: false,
        taskId: task.taskId,
        error: err instanceof Error ? err.message : String(err),
      })
    }
  }, [])

  const settingsLink = (
    <Link
      to="/promotion/settings"
      label={_(msg`Promotion settings`)}
      size="small"
      variant="ghost"
      color="secondary"
      shape="round"
      style={[a.justify_center]}>
      <ButtonIcon icon={SettingsIcon} size="lg" />
    </Link>
  )

  return (
    <Layout.Screen testID="promotionScreen">
      <Layout.Header.Outer>
        {gtMobile ? (
          <>
            <Layout.Header.Content>
              <Layout.Header.TitleText>
                <Trans>Promotion</Trans>
              </Layout.Header.TitleText>
            </Layout.Header.Content>
            <View style={[a.flex_row, a.align_center, a.gap_sm]}>
              {settingsLink}
              <Link
                to="/promotion/new"
                label={_(msg`New promotion`)}
                color="primary"
                size="small"
                variant="solid">
                <ButtonIcon icon={PlusIcon} position="left" />
                <ButtonText>
                  <Trans>New promotion</Trans>
                </ButtonText>
              </Link>
            </View>
          </>
        ) : (
          <>
            <Layout.Header.MenuButton />
            <Layout.Header.Content>
              <Layout.Header.TitleText>
                <Trans>Promotion</Trans>
              </Layout.Header.TitleText>
            </Layout.Header.Content>
            <Layout.Header.Slot>
              <View style={[a.flex_row, a.align_center]}>
                {settingsLink}
                <Link
                  to="/promotion/new"
                  label={_(msg`New promotion`)}
                  size="small"
                  variant="ghost"
                  color="secondary"
                  shape="round"
                  style={[a.justify_center]}>
                  <ButtonIcon icon={PlusIcon} size="lg" />
                </Link>
              </View>
            </Layout.Header.Slot>
          </>
        )}
      </Layout.Header.Outer>

      <Layout.Content>
        {!feedUris.length ? (
          <View style={[a.p_lg]}>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>
                Follow at least one feed generator with a promotion service to
                see tasks here.
              </Trans>
            </Text>
          </View>
        ) : tasksQuery.isPending ? (
          <View style={[a.p_lg, a.align_center]}>
            <ActivityIndicator />
          </View>
        ) : tasksQuery.isError ? (
          <View style={[a.p_lg, a.gap_md]}>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>Could not load promotion tasks.</Trans>
            </Text>
            <Button
              label={_(msg`Retry loading promotion tasks`)}
              size="small"
              variant="solid"
              color="primary"
              onPress={() => {
                void tasksQuery.refetch()
              }}>
              <ButtonText>
                <Trans>Retry</Trans>
              </ButtonText>
            </Button>
          </View>
        ) : tasks.length === 0 ? (
          <View style={[a.p_lg]}>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>No promotion tasks yet.</Trans>
            </Text>
          </View>
        ) : (
          <View style={[a.p_lg, a.gap_sm]}>
            {tasks.map(task => (
              <View
                key={`${task.serviceUrl}:${task.taskId}`}
                style={[
                  a.rounded_md,
                  a.border,
                  t.atoms.border_contrast_low,
                  a.p_md,
                  a.gap_sm,
                ]}>
                <View
                  style={[
                    a.flex_row,
                    a.align_center,
                    a.justify_between,
                    a.gap_sm,
                  ]}>
                  <Text style={[a.font_bold, a.flex_1]}>#{task.taskId}</Text>
                  {(() => {
                    const validationState = validationStateQuery.data?.get(
                      `${task.serviceUrl}::${task.taskId}`,
                    )
                    if (!validationState?.count) return null
                    return (
                      <View
                        style={[
                          a.flex_row,
                          a.align_center,
                          a.gap_xs,
                          a.rounded_full,
                          a.px_sm,
                          a.py_xs,
                          t.atoms.bg_contrast_25,
                        ]}>
                        <ShieldCheckIcon
                          size="xs"
                          fill={t.palette.positive_500}
                        />
                        <Text
                          style={[
                            a.text_sm,
                            a.font_bold,
                            {color: t.palette.positive_500},
                          ]}>
                          View: {validationState.count}
                        </Text>
                      </View>
                    )
                  })()}
                </View>
                {typeof task.postUri === 'string' && task.postUri ? (
                  <Text
                    numberOfLines={1}
                    style={[t.atoms.text_contrast_medium]}>
                    post: {task.postUri}
                  </Text>
                ) : null}
                {typeof task.postUri === 'string' && task.postUri ? (
                  <Text
                    numberOfLines={1}
                    style={[t.atoms.text_contrast_medium]}>
                    views:{' '}
                    {(
                      viewsQuery.data?.get(
                        `${task.serviceUrl}::${task.postUri}`,
                      ) ?? 0
                    ).toLocaleString()}
                  </Text>
                ) : null}
                <Text numberOfLines={1} style={[t.atoms.text_contrast_medium]}>
                  service: {task.serviceUrl}
                </Text>
                {typeof task.createdAt === 'string' && task.createdAt ? (
                  <Text style={[t.atoms.text_contrast_medium]}>
                    created: {task.createdAt}
                  </Text>
                ) : null}
                {(() => {
                  const taskKey = `${task.serviceUrl}::${task.taskId}`
                  const validationState =
                    validationStateQuery.data?.get(taskKey)
                  const hasAudit = validationState?.hasAudit ?? false
                  const validationCount = validationState?.count ?? 0
                  const hasPostUri =
                    typeof task.postUri === 'string' && Boolean(task.postUri)
                  return (
                    <View
                      style={[a.pt_xs, a.flex_row, a.align_center, a.gap_sm]}>
                      {hasPostUri ? (
                        <Button
                          label={_(msg`View promotion post`)}
                          size="small"
                          variant="outline"
                          color="secondary"
                          style={[a.flex_1]}
                          onPress={() => {
                            onViewPost(task.postUri as string)
                          }}>
                          <ButtonText>
                            <Trans>View post</Trans>
                          </ButtonText>
                        </Button>
                      ) : null}
                      {hasAudit ? (
                        <Button
                          label={_(msg`Validate promotion task`)}
                          size="small"
                          variant="outline"
                          color="secondary"
                          style={[a.flex_1]}
                          disabled={validatingTaskKey === taskKey}
                          onPress={() => {
                            void onValidateTask(task)
                          }}>
                          <ButtonIcon icon={ShieldCheckIcon} />
                          <ButtonText>
                            {validatingTaskKey === taskKey ? (
                              <Trans>Validating...</Trans>
                            ) : (
                              <Trans>Validate</Trans>
                            )}
                          </ButtonText>
                        </Button>
                      ) : (
                        <View
                          style={[
                            a.flex_1,
                            a.justify_center,
                            a.px_md,
                            a.border,
                            a.rounded_md,
                            t.atoms.border_contrast_low,
                          ]}>
                          <Text
                            style={[a.text_sm, t.atoms.text_contrast_medium]}>
                            <Trans>Local audit data required</Trans>
                          </Text>
                        </View>
                      )}
                      {validationCount > 0 ? (
                        <Button
                          label={_(msg`View promotion proof`)}
                          size="small"
                          variant="outline"
                          color="secondary"
                          style={[a.flex_1]}
                          onPress={() => {
                            void onViewProof(task)
                          }}>
                          <ButtonText>
                            <Trans>View proof</Trans>
                          </ButtonText>
                        </Button>
                      ) : null}
                    </View>
                  )
                })()}
              </View>
            ))}
          </View>
        )}
      </Layout.Content>
      <Modal
        transparent
        visible={proofViewer.visible}
        animationType="fade"
        onRequestClose={() => {
          setProofViewer({visible: false, loading: false})
        }}>
        <View
          style={[
            a.flex_1,
            a.justify_center,
            a.align_center,
            {backgroundColor: 'rgba(0, 0, 0, 0.45)'},
          ]}>
          <View
            style={[
              a.w_full,
              a.mx_lg,
              a.rounded_lg,
              a.border,
              a.p_lg,
              a.gap_md,
              t.atoms.bg,
              t.atoms.border_contrast_low,
              {maxWidth: 760, maxHeight: '80%'},
            ]}>
            <View
              style={[a.flex_row, a.align_center, a.justify_between, a.gap_sm]}>
              <View style={[a.flex_1, a.gap_xs]}>
                <Text style={[a.font_bold, a.text_lg]}>
                  <Trans>Proof JSON</Trans>
                </Text>
                {proofViewer.taskId ? (
                  <Text style={[a.text_sm, t.atoms.text_contrast_medium]}>
                    #{proofViewer.taskId}
                  </Text>
                ) : null}
              </View>
              <Button
                label={_(msg`Close proof viewer`)}
                size="small"
                variant="ghost"
                color="secondary"
                onPress={() => {
                  setProofViewer({visible: false, loading: false})
                }}>
                <ButtonText>
                  <Trans>Close</Trans>
                </ButtonText>
              </Button>
            </View>
            {proofViewer.loading ? (
              <View style={[a.py_xl, a.align_center, a.gap_sm]}>
                <ActivityIndicator />
                <Text style={[t.atoms.text_contrast_medium]}>
                  <Trans>Loading proof...</Trans>
                </Text>
              </View>
            ) : proofViewer.error ? (
              <View style={[a.gap_sm]}>
                <Text style={[a.font_bold]}>
                  <Trans>Could not load proof.</Trans>
                </Text>
                <Text style={[t.atoms.text_contrast_medium]}>
                  {proofViewer.error}
                </Text>
              </View>
            ) : (
              <ScrollView
                style={[a.w_full]}
                contentContainerStyle={[
                  a.p_md,
                  a.rounded_md,
                  t.atoms.bg_contrast_25,
                ]}>
                <Text
                  style={[a.text_sm, t.atoms.text, {fontFamily: 'monospace'}]}>
                  {JSON.stringify(proofViewer.data ?? {}, null, 2)}
                </Text>
              </ScrollView>
            )}
          </View>
        </View>
      </Modal>
    </Layout.Screen>
  )
}
