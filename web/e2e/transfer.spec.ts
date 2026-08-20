import { test, expect } from '@playwright/test'

// Migrating in and out, driven through the browser.
//
// The Go tests prove the conversions. What only a browser can show is whether
// somebody arriving from SecureCRT can actually complete the journey: choose
// a source, upload a folder they zipped on their desktop, read what would
// happen, commit it, and find their devices in the tree afterwards. And then
// leave again with an encrypted bundle.

const BASE = process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500'
const EMAIL = 'transfer@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const SECURECRT_ZIP = process.env.BKD_E2E_SECURECRT_ZIP ?? ''
const PUTTY_ZIP = process.env.BKD_E2E_PUTTY_ZIP ?? ''

test.beforeEach(async ({ page }) => {
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return
    const text = msg.text()
    if (text.startsWith('Failed to load resource')) return
    throw new Error(`console error: ${text}`)
  })
  page.on('pageerror', (err) => {
    throw new Error(`page error: ${err.message}`)
  })
})

async function signIn(page: import('@playwright/test').Page) {
  await page.goto(BASE)
  await page.getByLabel('Email address', { exact: true }).fill(EMAIL)
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()

  const enrol = page.getByRole('heading', { name: 'Set up your vault' })
  const unlock = page.getByRole('heading', { name: 'Unlock your vault' })
  await expect(enrol.or(unlock)).toBeVisible()

  if (await enrol.isVisible()) {
    await page.getByLabel('Choose a passphrase', { exact: true }).fill(PASSPHRASE)
    await page.getByLabel('Repeat it', { exact: true }).fill(PASSPHRASE)
    await page.getByRole('button', { name: 'Create vault' }).click()
  } else {
    await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE)
    await page.getByRole('button', { name: 'Unlock' }).click()
  }

  await expect(page.getByRole('button', { name: 'Terminal' })).toHaveAttribute(
    'aria-current', 'page')
}

async function openTransfer(page: import('@playwright/test').Page) {
  await page.getByRole('button', { name: 'Import / export' }).click()
  await expect(page.getByRole('heading', { name: 'Import', exact: true })).toBeVisible()
}

/** upload picks a source and hands over a file, returning the preview card. */
async function upload(
  page: import('@playwright/test').Page,
  source: string,
  path: string,
) {
  await page.getByRole('combobox', { name: 'Where from' }).selectOption(source)
  await page.getByLabel('Configuration to import').setInputFiles(path)

  const preview = page.locator('.card').filter({
    has: page.getByRole('heading', { name: 'What this would do' }),
  })
  await expect(preview).toBeVisible({ timeout: 20_000 })
  return preview
}

test('previews a SecureCRT folder without writing anything', async ({ page }) => {
  test.skip(SECURECRT_ZIP === '', 'BKD_E2E_SECURECRT_ZIP is not set')

  await signIn(page)
  await openTransfer(page)

  const preview = await upload(page, 'securecrt', SECURECRT_ZIP)
  await expect(preview).toContainText('2 new')

  // Discarding takes the preview away...
  await page.getByRole('button', { name: 'Discard' }).click()
  await expect(page.getByRole('heading', { name: 'What this would do' })).toHaveCount(0)

  // ...and the tree is the witness that nothing was ever written. Checked
  // after the discard rather than before, so this also proves the discard did
  // not somehow commit on its way out.
  await page.getByRole('button', { name: 'Terminal' }).click()
  await expect(page.getByText('core-sw-01')).toHaveCount(0)
})

test('imports a SecureCRT folder and the devices appear in the tree', async ({ page }) => {
  test.skip(SECURECRT_ZIP === '', 'BKD_E2E_SECURECRT_ZIP is not set')

  await signIn(page)
  await openTransfer(page)

  await upload(page, 'securecrt', SECURECRT_ZIP)
  await page.getByRole('button', { name: 'Import', exact: true }).click()

  await expect(page.getByRole('heading', { name: 'Imported' })).toBeVisible({
    timeout: 20_000,
  })

  // The connections are in the workspace, under the folder SecureCRT had them
  // in — which is the whole point of importing rather than retyping. No page
  // reload: the tab switch alone has to be enough, or somebody who has just
  // imported two hundred devices sees an empty tree and concludes it failed.
  await page.getByRole('button', { name: 'Terminal' }).click()
  await expect(page.getByText('core-sw-01')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Edge routers')).toBeVisible()
})

test('a PuTTY key file is converted on the way in', async ({ page }) => {
  test.skip(PUTTY_ZIP === '', 'BKD_E2E_PUTTY_ZIP is not set')

  await signIn(page)
  await openTransfer(page)

  const preview = await upload(page, 'putty', PUTTY_ZIP)

  // The preview says so before anything is written, because "your keys came
  // across" is the single thing a PuTTY user most needs to know.
  await expect(preview).toContainText('Converted 1 PuTTY key file')

  await page.getByRole('button', { name: 'Import', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Imported' })).toBeVisible({
    timeout: 20_000,
  })

  // The key is a credential now, with a fingerprint the list can show without
  // opening the vault.
  await page.getByRole('button', { name: 'Credentials' }).click()
  await expect(page.getByText(/PuTTY: core/)).toBeVisible()
  await expect(page.getByText(/SHA256:/).first()).toBeVisible()
})

test('exports an encrypted bundle', async ({ page }) => {
  await signIn(page)
  await openTransfer(page)

  await page.getByRole('combobox', { name: 'Format' }).selectOption('bundle')
  await page.getByLabel('Passphrase for the bundle').fill('a long enough bundle passphrase')
  await page.getByLabel('Repeat it', { exact: true }).fill('a long enough bundle passphrase')

  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export', exact: true }).click()

  const file = await download
  expect(file.suggestedFilename()).toMatch(/\.bkbundle$/)

  // The first line of a bundle is a readable header; the second is
  // ciphertext. Checking the header is what proves this is a bundle rather
  // than an error page the browser happened to save.
  const path = await file.path()
  const { readFileSync } = await import('node:fs')
  const contents = readFileSync(path, 'utf8')

  const header = JSON.parse(contents.split('\n')[0])
  expect(header.format).toBe('bkbundle')
  expect(contents).not.toContain('core-sw-01')
})

test('a plaintext export needs no confirmation without secrets, and is refused with them',
  async ({ page }) => {
    // This instance has policy.allow_plaintext_export off, which is the
    // default and the setting most deployments will run.
    await signIn(page)
    await openTransfer(page)

    await page.getByRole('combobox', { name: 'Format' }).selectOption('json')

    // Asking for the secrets is refused, and the screen says how to proceed
    // rather than only that it will not.
    await expect(page.getByText(/disabled on this server/)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Export', exact: true })).toBeDisabled()

    // Without them the same format downloads: a device list carries no
    // credentials, so the switch that exists to stop credentials leaving has
    // nothing to say about it.
    await page.getByLabel('Include keys and passwords').uncheck()
    await expect(page.getByRole('button', { name: 'Export', exact: true })).toBeEnabled()

    const download = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export', exact: true }).click()

    const file = await download
    expect(file.suggestedFilename()).toMatch(/\.json$/)

    const { readFileSync } = await import('node:fs')
    const exported = JSON.parse(readFileSync(await file.path(), 'utf8'))
    expect(Array.isArray(exported.sessions)).toBe(true)
  })
