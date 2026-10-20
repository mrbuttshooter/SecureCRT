import { test, expect, type Locator, type Page } from '@playwright/test'
import { closeWindow, openPage, signIn as signInWith } from './ui'

// Migrating in and out, driven through the browser.
//
// The Go tests prove the conversions. What only a browser can show is whether
// somebody arriving from SecureCRT can actually complete the journey: choose
// a source, upload a folder they zipped on their desktop, read what would
// happen, commit it, and find their devices in the tree afterwards. And then
// leave again with an encrypted bundle.

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

async function signIn(page: Page) {
  await signInWith(page, { email: EMAIL, password: PASSWORD, passphrase: PASSPHRASE })
}

/** openTransfer opens File > Import and export, and returns its window. */
async function openTransfer(page: Page): Promise<Locator> {
  const win = await openPage(page, 'transfer')
  // Exact: the window's own title is "Import and export".
  await expect(win.getByRole('heading', { name: 'Import', exact: true })).toBeVisible()
  return win
}

/** upload picks a source and hands over a file, returning the preview card. */
async function upload(
  win: Locator,
  source: string,
  path: string,
) {
  await win.getByRole('combobox', { name: 'Where from' }).selectOption(source)
  await win.getByLabel('Configuration to import').setInputFiles(path)

  const preview = win.locator('.card').filter({
    has: win.getByRole('heading', { name: 'What this would do' }),
  })
  await expect(preview).toBeVisible({ timeout: 20_000 })
  return preview
}

test('previews a SecureCRT folder without writing anything', async ({ page }) => {
  test.skip(SECURECRT_ZIP === '', 'BKD_E2E_SECURECRT_ZIP is not set')

  await signIn(page)
  const win = await openTransfer(page)

  const preview = await upload(win, 'securecrt', SECURECRT_ZIP)
  await expect(preview).toContainText('2 new')

  // Discarding takes the preview away...
  await win.getByRole('button', { name: 'Discard' }).click()
  await expect(win.getByRole('heading', { name: 'What this would do' })).toHaveCount(0)

  // ...and the tree is the witness that nothing was ever written. Checked
  // after the discard rather than before, so this also proves the discard did
  // not somehow commit on its way out.
  await closeWindow(win)
  await expect(page.locator('.sidebar').getByText('core-sw-01')).toHaveCount(0)
})

test('imports a SecureCRT folder and the devices appear in the tree', async ({ page }) => {
  test.skip(SECURECRT_ZIP === '', 'BKD_E2E_SECURECRT_ZIP is not set')

  await signIn(page)
  const win = await openTransfer(page)

  await upload(win, 'securecrt', SECURECRT_ZIP)
  await win.getByRole('button', { name: 'Import', exact: true }).click()

  await expect(win.getByRole('heading', { name: 'Imported' })).toBeVisible({
    timeout: 20_000,
  })

  // The connections are in the workspace, under the folder SecureCRT had them
  // in — which is the whole point of importing rather than retyping. No page
  // reload: the tab switch alone has to be enough, or somebody who has just
  // imported two hundred devices sees an empty tree and concludes it failed.
  await closeWindow(win)
  await expect(page.locator('.sidebar').getByText('core-sw-01').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.sidebar').getByText('Edge routers')).toBeVisible()
})

test('a PuTTY key file is converted on the way in', async ({ page }) => {
  test.skip(PUTTY_ZIP === '', 'BKD_E2E_PUTTY_ZIP is not set')

  await signIn(page)
  const win = await openTransfer(page)

  const preview = await upload(win, 'putty', PUTTY_ZIP)

  // The preview says so before anything is written, because "your keys came
  // across" is the single thing a PuTTY user most needs to know.
  await expect(preview).toContainText('Converted 1 PuTTY key file')

  await win.getByRole('button', { name: 'Import', exact: true }).click()
  await expect(win.getByRole('heading', { name: 'Imported' })).toBeVisible({
    timeout: 20_000,
  })

  // The key is a credential now, with a fingerprint the list can show without
  // opening the vault. One window at a time: this one closes first.
  await closeWindow(win)
  const credentials = await openPage(page, 'credentials')
  await expect(credentials.getByText(/PuTTY: core/)).toBeVisible()
  await expect(credentials.getByText(/SHA256:/).first()).toBeVisible()
})

test('exports an encrypted bundle', async ({ page }) => {
  await signIn(page)
  const win = await openTransfer(page)

  await win.getByRole('combobox', { name: 'Format' }).selectOption('bundle')
  await win.getByLabel('Passphrase for the bundle').fill('a long enough bundle passphrase')
  await win.getByLabel('Repeat it', { exact: true }).fill('a long enough bundle passphrase')

  const download = page.waitForEvent('download')
  await win.getByRole('button', { name: 'Export', exact: true }).click()

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
    const win = await openTransfer(page)

    await win.getByRole('combobox', { name: 'Format' }).selectOption('json')

    // Asking for the secrets is refused, and the screen says how to proceed
    // rather than only that it will not.
    await expect(win.getByText(/disabled on this server/)).toBeVisible()
    await expect(win.getByRole('button', { name: 'Export', exact: true })).toBeDisabled()

    // Without them the same format downloads: a device list carries no
    // credentials, so the switch that exists to stop credentials leaving has
    // nothing to say about it.
    await win.getByLabel('Include keys and passwords').uncheck()
    await expect(win.getByRole('button', { name: 'Export', exact: true })).toBeEnabled()

    const download = page.waitForEvent('download')
    await win.getByRole('button', { name: 'Export', exact: true }).click()

    const file = await download
    expect(file.suggestedFilename()).toMatch(/\.json$/)

    const { readFileSync } = await import('node:fs')
    const exported = JSON.parse(readFileSync(await file.path(), 'utf8'))
    expect(Array.isArray(exported.sessions)).toBe(true)
  })
