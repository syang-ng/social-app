import {useCallback, useEffect, useRef, useState} from 'react'
import {Modal, View} from 'react-native'
import {setStringAsync} from 'expo-clipboard'
import {msg} from '@lingui/core/macro'
import {useLingui} from '@lingui/react'
import {Trans} from '@lingui/react/macro'
import {useFocusEffect} from '@react-navigation/native'

import {
  type CommonNavigatorParams,
  type NativeStackScreenProps,
} from '#/lib/routes/types'
import {
  exportVarMasterSeed,
  getStoredVarMasterSeedBase64,
  importVarMasterSeed,
} from '#/lib/var/keyring'
import {ensureVarUserKeypair} from '#/lib/var/user-keypair'
import {ensureVarVerifierKeypair} from '#/lib/var/verifier-keypair'
import {useAgent} from '#/state/session'
import {useSetMinimalShellMode} from '#/state/shell'
import {atoms as a, useTheme} from '#/alf'
import {Button, ButtonText} from '#/components/Button'
import * as TextField from '#/components/forms/TextField'
import * as Layout from '#/components/Layout'
import * as Toast from '#/components/Toast'
import {Text} from '#/components/Typography'
import {IS_WEB} from '#/env'

type Props = NativeStackScreenProps<CommonNavigatorParams, 'PromotionSettings'>

type BarcodeDetectionResult = {
  rawValue?: string
}

type BarcodeDetectorLike = {
  detect: (source: ImageBitmapSource) => Promise<BarcodeDetectionResult[]>
}

type BarcodeDetectorCtor = new (options: {
  formats: string[]
}) => BarcodeDetectorLike

export function PromotionSettingsScreen({}: Props) {
  const {_} = useLingui()
  const t = useTheme()
  const agent = useAgent()
  const setMinimalShellMode = useSetMinimalShellMode()
  const [importValue, setImportValue] = useState('')
  const [importError, setImportError] = useState<string | null>(null)
  const [isImporting, setIsImporting] = useState(false)
  const [isGenerating, setIsGenerating] = useState(false)
  const [exportConfirmVisible, setExportConfirmVisible] = useState(false)
  const [exportVisible, setExportVisible] = useState(false)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const qrInputRef = useRef<HTMLInputElement | null>(null)

  useFocusEffect(
    useCallback(() => {
      setMinimalShellMode(false)
    }, [setMinimalShellMode]),
  )

  const did = agent.session?.did
  const [exportedSeed, setExportedSeed] = useState<string | null>(null)
  const hasSeed = Boolean(did && getStoredVarMasterSeedBase64(did))

  useEffect(() => {
    let disposed = false
    if (!did) {
      setExportedSeed(null)
      return
    }
    void exportVarMasterSeed(did).then(value => {
      if (!disposed) setExportedSeed(value)
    })
    return () => {
      disposed = true
    }
  }, [did, hasSeed])

  const onGenerate = useCallback(async () => {
    if (!did) return
    try {
      setIsGenerating(true)
      await ensureVarUserKeypair(agent)
      await ensureVarVerifierKeypair(agent)
      Toast.show(_(msg`Promotion seed created`))
    } catch (err) {
      Toast.show(_(msg`Could not create promotion seed`), {type: 'error'})
    } finally {
      setIsGenerating(false)
    }
  }, [_, agent, did])

  const onImport = useCallback(async () => {
    if (!did) return
    try {
      setIsImporting(true)
      setImportError(null)
      await importVarMasterSeed(did, importValue)
      await ensureVarUserKeypair(agent)
      await ensureVarVerifierKeypair(agent)
      setImportValue('')
      Toast.show(_(msg`Promotion seed imported`))
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      setImportError(message)
      Toast.show(_(msg`Could not import promotion seed`), {type: 'error'})
    } finally {
      setIsImporting(false)
    }
  }, [_, agent, did, importValue])

  const onCopyExport = useCallback(async () => {
    if (!exportedSeed) return
    await setStringAsync(exportedSeed)
    Toast.show(_(msg`Promotion seed copied`))
  }, [_, exportedSeed])

  const applyImportedSeed = useCallback(
    async (value: string) => {
      if (!did) return
      try {
        setIsImporting(true)
        setImportError(null)
        setImportValue(value)
        await importVarMasterSeed(did, value)
        await ensureVarUserKeypair(agent)
        await ensureVarVerifierKeypair(agent)
        setImportValue('')
        Toast.show(_(msg`Promotion seed imported`))
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        setImportError(message)
        Toast.show(_(msg`Could not import promotion seed`), {type: 'error'})
      } finally {
        setIsImporting(false)
      }
    },
    [_, agent, did],
  )

  return (
    <Layout.Screen testID="promotionSettingsScreen">
      <Layout.Header.Outer>
        <Layout.Header.BackButton />
        <Layout.Header.Content align="left">
          <Layout.Header.TitleText>
            <Trans>Promotion settings</Trans>
          </Layout.Header.TitleText>
        </Layout.Header.Content>
        <Layout.Header.Slot />
      </Layout.Header.Outer>
      <Layout.Content>
        <View style={[a.p_lg, a.gap_lg]}>
          <View style={[a.gap_sm]}>
            <Text style={[a.text_xl, a.font_bold]}>
              <Trans>Promotion seed</Trans>
            </Text>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>
                One local recovery phrase now derives both your X25519 user key
                and your Ed25519 verifier key. Export it to move promotion
                access across devices.
              </Trans>
            </Text>
          </View>

          <View
            style={[
              a.rounded_md,
              a.border,
              a.p_md,
              a.gap_sm,
              t.atoms.border_contrast_low,
            ]}>
            <Text style={[a.font_bold]}>
              {hasSeed ? (
                <Trans>Seed is ready</Trans>
              ) : (
                <Trans>No seed yet</Trans>
              )}
            </Text>
            <Text style={[t.atoms.text_contrast_medium]}>
              {hasSeed ? (
                <Trans>
                  This device can derive and restore your promotion keys from
                  the saved seed.
                </Trans>
              ) : (
                <Trans>
                  Generate a new seed on this device or import one from another
                  device.
                </Trans>
              )}
            </Text>
            <View style={[a.flex_row, a.gap_sm]}>
              {!hasSeed ? (
                <Button
                  label={_(msg`Generate promotion seed`)}
                  size="small"
                  variant="solid"
                  color="primary"
                  disabled={!did || isGenerating}
                  onPress={() => {
                    void onGenerate()
                  }}>
                  <ButtonText>
                    {isGenerating ? (
                      <Trans>Generating...</Trans>
                    ) : (
                      <Trans>Generate</Trans>
                    )}
                  </ButtonText>
                </Button>
              ) : (
                <Button
                  label={_(msg`Export promotion seed`)}
                  size="small"
                  variant="outline"
                  color="secondary"
                  disabled={!exportedSeed}
                  onPress={() => {
                    setExportConfirmVisible(true)
                  }}>
                  <ButtonText>
                    <Trans>Export seed</Trans>
                  </ButtonText>
                </Button>
              )}
            </View>
          </View>

          <View
            style={[
              a.rounded_md,
              a.border,
              a.p_md,
              a.gap_sm,
              t.atoms.border_contrast_low,
            ]}>
            <Text style={[a.font_bold]}>
              <Trans>Import existing seed</Trans>
            </Text>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>
                Paste a previously exported recovery phrase to restore the same
                promotion keys on this device.
              </Trans>
            </Text>
            <TextField.Root isInvalid={Boolean(importError)}>
              <TextField.Input
                label={_(msg`Promotion recovery phrase`)}
                value={importValue}
                onChangeText={value => {
                  setImportValue(value)
                  if (importError) setImportError(null)
                }}
                autoCapitalize="none"
                autoCorrect={false}
                placeholder={_(msg`Paste recovery words`)}
              />
            </TextField.Root>
            {importError ? (
              <Text style={[a.text_sm, {color: t.palette.negative_500}]}>
                {importError}
              </Text>
            ) : null}
            <View style={[a.flex_row, a.gap_sm]}>
              <Button
                label={_(msg`Import promotion seed`)}
                size="small"
                variant="solid"
                color="primary"
                disabled={!did || !importValue.trim() || isImporting}
                onPress={() => {
                  void onImport()
                }}>
                <ButtonText>
                  {isImporting ? (
                    <Trans>Importing...</Trans>
                  ) : (
                    <Trans>Import</Trans>
                  )}
                </ButtonText>
              </Button>
              {IS_WEB ? (
                <>
                  <Button
                    label={_(msg`Import promotion seed file`)}
                    size="small"
                    variant="outline"
                    color="secondary"
                    disabled={isImporting}
                    onPress={() => {
                      fileInputRef.current?.click()
                    }}>
                    <ButtonText>
                      <Trans>Import file</Trans>
                    </ButtonText>
                  </Button>
                  <Button
                    label={_(msg`Scan QR image for promotion seed`)}
                    size="small"
                    variant="outline"
                    color="secondary"
                    disabled={isImporting}
                    onPress={() => {
                      qrInputRef.current?.click()
                    }}>
                    <ButtonText>
                      <Trans>Scan QR image</Trans>
                    </ButtonText>
                  </Button>
                </>
              ) : null}
            </View>
          </View>
        </View>
      </Layout.Content>

      {IS_WEB ? (
        <>
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,text/plain"
            style={{display: 'none'}}
            onChange={event => {
              void (async () => {
                const file = event.currentTarget.files?.[0]
                event.currentTarget.value = ''
                if (!file) return
                const text = await file.text()
                await applyImportedSeed(text)
              })()
            }}
          />
          <input
            ref={qrInputRef}
            type="file"
            accept="image/*"
            style={{display: 'none'}}
            onChange={event => {
              void (async () => {
                const file = event.currentTarget.files?.[0]
                event.currentTarget.value = ''
                if (!file) return
                try {
                  const detectorCtor = (
                    globalThis as typeof globalThis & {
                      BarcodeDetector?: BarcodeDetectorCtor
                    }
                  ).BarcodeDetector
                  if (!detectorCtor) {
                    throw new Error('BarcodeDetectorUnavailable')
                  }
                  const detector = new detectorCtor({formats: ['qr_code']})
                  const image = new Image()
                  const objectUrl = URL.createObjectURL(file)
                  image.src = objectUrl
                  await image.decode()
                  const results = await detector.detect(image)
                  URL.revokeObjectURL(objectUrl)
                  const rawValue =
                    Array.isArray(results) && results[0]?.rawValue
                      ? String(results[0].rawValue)
                      : ''
                  if (!rawValue) {
                    throw new Error('QrCodeNotFound')
                  }
                  await applyImportedSeed(rawValue)
                } catch (err) {
                  const message =
                    err instanceof Error ? err.message : String(err)
                  setImportError(message)
                  Toast.show(_(msg`Could not scan promotion seed QR`), {
                    type: 'error',
                  })
                }
              })()
            }}
          />
        </>
      ) : null}

      <Modal
        transparent
        visible={exportConfirmVisible}
        animationType="fade"
        onRequestClose={() => setExportConfirmVisible(false)}>
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
              {maxWidth: 560},
            ]}>
            <Text style={[a.text_lg, a.font_bold]}>
              <Trans>Reveal promotion seed?</Trans>
            </Text>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>
                Anyone who sees this seed can restore your promotion keys on
                another device. Only continue if you are in a private place and
                ready to store it securely.
              </Trans>
            </Text>
            <View style={[a.flex_row, a.justify_between, a.gap_sm]}>
              <Button
                label={_(msg`Cancel seed export reveal`)}
                size="small"
                variant="ghost"
                color="secondary"
                onPress={() => {
                  setExportConfirmVisible(false)
                }}>
                <ButtonText>
                  <Trans>Cancel</Trans>
                </ButtonText>
              </Button>
              <Button
                label={_(msg`Show promotion seed now`)}
                size="small"
                variant="solid"
                color="primary"
                onPress={() => {
                  setExportConfirmVisible(false)
                  setExportVisible(true)
                }}>
                <ButtonText>
                  <Trans>Show seed</Trans>
                </ButtonText>
              </Button>
            </View>
          </View>
        </View>
      </Modal>

      <Modal
        transparent
        visible={exportVisible}
        animationType="fade"
        onRequestClose={() => setExportVisible(false)}>
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
              {maxWidth: 640},
            ]}>
            <Text style={[a.text_lg, a.font_bold]}>
              <Trans>Export promotion seed</Trans>
            </Text>
            <Text style={[t.atoms.text_contrast_medium]}>
              <Trans>
                Store these words securely. Anyone with them can restore your
                promotion keys on another device.
              </Trans>
            </Text>
            <View style={[a.rounded_md, a.p_md, t.atoms.bg_contrast_25]}>
              <Text selectable style={[a.text_sm, t.atoms.text]}>
                {exportedSeed || ''}
              </Text>
            </View>
            <View style={[a.flex_row, a.justify_between, a.gap_sm]}>
              <Button
                label={_(msg`Close seed export`)}
                size="small"
                variant="ghost"
                color="secondary"
                onPress={() => {
                  setExportVisible(false)
                }}>
                <ButtonText>
                  <Trans>Close</Trans>
                </ButtonText>
              </Button>
              <Button
                label={_(msg`Copy promotion seed`)}
                size="small"
                variant="solid"
                color="primary"
                disabled={!exportedSeed}
                onPress={() => {
                  void onCopyExport()
                }}>
                <ButtonText>
                  <Trans>Copy seed</Trans>
                </ButtonText>
              </Button>
            </View>
          </View>
        </View>
      </Modal>
    </Layout.Screen>
  )
}
