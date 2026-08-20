import { test, expect, type Page, type Locator } from '@playwright/test'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// The file browser, driven through a real browser against two real SFTP
// servers.
//
// The Go tests already prove the protocol and the API. What these prove is
// the half no Go test can reach: that a file dropped on a pane in Chromium
// arrives on a filesystem, that a download comes back byte for byte, that a
// directory dragged from one pane to the other really does move host to host,
// and that the editor writes what it shows.
//
// Every assertion about a file ends at readFileSync in this process, because
// the test SSH servers serve the actual filesystem.

const BASE = process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500'
// Its own account: the suites share an instance, and sharing an account
// would mean sharing a vault, a credential list and a known-hosts list with
// whichever spec file happened to run first.
const EMAIL = 'files@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const SSH_HOST = process.env.BKD_E2E_SSH_HOST ?? '127.0.0.1'
const SSH_PORT = process.env.BKD_E2E_SSH_PORT ?? ''
const SSH_PORT_2 = process.env.BKD_E2E_SSH_PORT_2 ?? ''
const SSH_USER = process.env.BKD_E2E_SSH_USER ?? 'tester'
const SSH_PASSWORD = process.env.BKD_E2E_SSH_PASSWORD ?? ''

test.skip(!SSH_PORT || !SSH_PORT_2, 'no test SSH servers; run through scripts/e2e.sh')

/** A directory on the real filesystem both this test and the SSH servers see. */
let workspace: string

test.beforeAll(() => {
  workspace = mkdtempSync(join(tmpdir(), 'bkd-files-e2e-'))
})

test.afterAll(() => {
  rmSync(workspace, { recursive: true, force: true })
})

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

// --- helpers ----------------------------------------------------------------

async function signIn(page: Page) {
  await page.goto(BASE)

  const workspaceTab = page.getByRole('button', { name: 'Terminal' })
  const signInButton = page.getByRole('button', { name: 'Sign in' })
  const enrol = page.getByRole('heading', { name: 'Set up your vault' })
  const unlock = page.getByRole('heading', { name: 'Unlock your vault' })

  await expect(workspaceTab.or(signInButton).or(enrol).or(unlock)).toBeVisible()

  if (await signInButton.isVisible()) {
    await page.getByLabel('Email address', { exact: true }).fill(EMAIL)
    await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
    await signInButton.click()
    await expect(workspaceTab.or(enrol).or(unlock)).toBeVisible()
  }

  if (await enrol.isVisible()) {
    await page.getByLabel('Choose a passphrase', { exact: true }).fill(PASSPHRASE)
    await page.getByLabel('Repeat it', { exact: true }).fill(PASSPHRASE)
    await page.getByRole('button', { name: 'Create vault' }).click()
  } else if (await unlock.isVisible()) {
    await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE)
    await page.getByRole('button', { name: 'Unlock' }).click()
  }

  await expect(workspaceTab).toHaveAttribute('aria-current', 'page')
}

/** ensureCredential stores the test hosts' password once. */
async function ensureCredential(page: Page, name: string) {
  await page.getByRole('button', { name: 'Credentials' }).click()
  await expect(page.getByRole('heading', { name: 'Credentials' })).toBeVisible()

  if (await page.getByText(name, { exact: true }).count()) return

  await page.getByRole('button', { name: 'Add password' }).click()
  await page.getByLabel('Name', { exact: true }).fill(name)
  await page.getByLabel('Username (optional)', { exact: true }).fill(SSH_USER)
  await page.getByLabel('Secret', { exact: true }).fill(SSH_PASSWORD)
  await page.getByRole('button', { name: 'Save', exact: true }).click()

  await expect(page.getByText(name, { exact: true }).first()).toBeVisible()
}

/** ensureConnection saves a connection pointing at one of the test hosts. */
async function ensureConnection(page: Page, name: string, port: string, credentialName: string) {
  await ensureCredential(page, credentialName)

  await page.getByRole('button', { name: 'Terminal' }).click()
  if (await page.getByRole('button', { name, exact: true }).count()) return

  await page.getByRole('button', { name: 'New connection', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'New connection' })).toBeVisible()

  await page.getByLabel('Name', { exact: true }).fill(name)
  await page.getByLabel('Hostname or address', { exact: true }).fill(SSH_HOST)
  await page.getByLabel('Port', { exact: true }).fill(port)
  await page.getByLabel('Username on the remote host', { exact: true }).fill(SSH_USER)

  const credentialField = page.getByRole('combobox', { name: 'Credential' })
  const value = await credentialField.evaluate(
    (el, wanted) =>
      Array.from((el as HTMLSelectElement).options)
        .find((option) => option.text.startsWith(wanted))?.value ?? '',
    credentialName,
  )
  expect(value, `no option for the credential "${credentialName}"`).toBeTruthy()
  await credentialField.selectOption(value)

  await page.getByRole('button', { name: 'Create connection' }).click()
  await expect(page.getByRole('heading', { name: 'New connection' })).toBeHidden()
}

/**
 * openPane points a pane at a connection and navigates it to a directory,
 * accepting the host key on first contact.
 */
async function openPane(page: Page, side: 'left' | 'right', connection: string, directory: string) {
  const pane = page.getByTestId(`file-pane-${side}`)

  // Options read "<name> — <host>" and carry the connection's ID as their
  // value, which the test has no other way to learn. A collapsed select
  // renders no text, so they are read from the DOM rather than matched with a
  // text locator.
  const select = page.getByRole('combobox', { name: `Host for the ${side} pane` })
  const value = await select.evaluate((el, wanted) =>
    Array.from((el as HTMLSelectElement).options)
      .find((option) => option.text.startsWith(wanted))?.value ?? '', connection)
  expect(value, `no option for the connection "${connection}"`).toBeTruthy()
  await select.selectOption(value)

  const prompt = pane.getByRole('alertdialog', { name: 'Unrecognised host key' })
  const field = page.getByLabel(`Path on the ${side} pane`)

  // Wait for the pane to settle into one of its two outcomes rather than
  // sampling once: the dialog appears a round trip after the select fires,
  // and checking before it renders silently skips the acceptance and leaves
  // the pane closed for the rest of the test.
  await expect(async () => {
    const prompting = await prompt.isVisible()
    const ready = await field.isEnabled()
    expect(prompting || ready, 'the pane neither opened nor asked about the host key').toBe(true)
  }).toPass({ timeout: 30_000 })

  if (await prompt.isVisible()) {
    await expect(pane.getByTestId('host-key-fingerprint')).toContainText('SHA256:')
    await pane.getByRole('button', { name: /fingerprint matches/ }).click()
    await expect(field).toBeEnabled({ timeout: 30_000 })
  }

  await goTo(page, side, directory)
  return pane
}

/** goTo types a path into a pane's path bar. */
async function goTo(page: Page, side: 'left' | 'right', directory: string) {
  const field = page.getByLabel(`Path on the ${side} pane`)
  await expect(field).toBeEnabled({ timeout: 20_000 })
  await field.fill(directory)
  await field.press('Enter')
  await expect(field).toHaveValue(directory, { timeout: 20_000 })
}

/** row finds a listing row by filename. */
function row(pane: Locator, name: string): Locator {
  return pane.getByRole('row').filter({ has: pane.page().getByRole('button', { name, exact: true }) })
}

/** here makes a subdirectory of the shared workspace for one test. */
function here(name: string): string {
  const dir = join(workspace, name)
  mkdirSync(dir, { recursive: true })
  return dir
}

// --- tests ------------------------------------------------------------------

test('browses a directory and shows sizes, modes and owners', async ({ page }) => {
  const dir = here('browse')
  writeFileSync(join(dir, 'notes.txt'), 'twenty-four bytes long..')
  mkdirSync(join(dir, 'subdir'), { recursive: true })

  await signIn(page)
  await ensureConnection(page, 'Host A', SSH_PORT, 'Test host password')

  await page.getByRole('button', { name: 'Files' }).click()
  const pane = await openPane(page, 'left', 'Host A', dir)

  // Directories first, which is what the server sorted and what a file
  // manager is expected to show.
  const rows = pane.getByRole('row')
  await expect(rows.nth(1)).toContainText('subdir')

  const file = row(pane, 'notes.txt')
  await expect(file).toContainText('24 B')
  await expect(file).toContainText('-rw-')
})

test('uploads a file dropped from the desktop', async ({ page }) => {
  const dir = here('upload')

  await signIn(page)
  await ensureConnection(page, 'Host A', SSH_PORT, 'Test host password')

  await page.getByRole('button', { name: 'Files' }).click()
  const pane = await openPane(page, 'left', 'Host A', dir)

  // The file picker is the same code path the drop handler uses, and is what
  // Playwright can drive.
  const contents = 'uploaded through the browser\n'
  await page.getByLabel('Upload to the left pane').setInputFiles({
    name: 'uploaded.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from(contents),
  })

  // It appears in the listing...
  await expect(row(pane, 'uploaded.txt')).toBeVisible({ timeout: 20_000 })

  // ...and, far more importantly, it is on the filesystem.
  await expect(async () => {
    expect(existsSync(join(dir, 'uploaded.txt'))).toBe(true)
    expect(readFileSync(join(dir, 'uploaded.txt'), 'utf8')).toBe(contents)
  }).toPass({ timeout: 20_000 })
})

test('downloads a file byte for byte', async ({ page }) => {
  const dir = here('download')

  // Binary, and larger than one SFTP packet, so any offset mistake in the
  // streaming path shows up as corruption rather than as a wrong byte count.
  const payload = Buffer.alloc(150 * 1024)
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 37) % 256
  writeFileSync(join(dir, 'payload.bin'), payload)

  await signIn(page)
  await ensureConnection(page, 'Host A', SSH_PORT, 'Test host password')

  await page.getByRole('button', { name: 'Files' }).click()
  const pane = await openPane(page, 'left', 'Host A', dir)

  const target = row(pane, 'payload.bin')
  await target.hover()

  const download = await Promise.race([
    page.waitForEvent('download'),
    target.getByRole('link', { name: 'Download' }).click().then(() => page.waitForEvent('download')),
  ])

  expect(download.suggestedFilename()).toBe('payload.bin')

  const saved = join(workspace, 'downloaded.bin')
  await download.saveAs(saved)
  expect(readFileSync(saved).equals(payload)).toBe(true)
})

test('copies a directory from one host straight to the other', async ({ page }) => {
  const source = here('copy-source')
  const dest = here('copy-dest')

  mkdirSync(join(source, 'bundle', 'conf'), { recursive: true })
  writeFileSync(join(source, 'bundle', 'app.bin'), 'the binary')
  writeFileSync(join(source, 'bundle', 'conf', 'settings.yaml'), 'key: value')

  await signIn(page)
  await ensureConnection(page, 'Host A', SSH_PORT, 'Test host password')
  await ensureConnection(page, 'Host B', SSH_PORT_2, 'Test host password')

  await page.getByRole('button', { name: 'Files' }).click()
  const left = await openPane(page, 'left', 'Host A', source)
  await openPane(page, 'right', 'Host B', dest)

  // Drag "bundle" from the left pane onto the right one. HTML5 drag-and-drop
  // is not something Playwright can synthesise across elements reliably, so
  // the DataTransfer is built and dispatched directly — the same events the
  // browser would fire.
  await left.getByRole('button', { name: 'bundle', exact: true }).hover()

  await page.evaluate(() => {
    const from = document.querySelector('[data-testid="file-pane-left"]')
    const to = document.querySelector('[data-testid="file-pane-right"]')
    if (!from || !to) throw new Error('a pane is missing')

    const source = Array.from(from.querySelectorAll('[role="row"]'))
      .find((r) => r.textContent?.includes('bundle'))
    if (!source) throw new Error('the source row is missing')

    const transfer = new DataTransfer()
    source.dispatchEvent(new DragEvent('dragstart', { dataTransfer: transfer, bubbles: true }))
    to.dispatchEvent(new DragEvent('dragover', { dataTransfer: transfer, bubbles: true }))
    to.dispatchEvent(new DragEvent('drop', { dataTransfer: transfer, bubbles: true }))
  })

  // The transfer is reported while it runs...
  await expect(page.getByRole('heading', { name: 'Transfers' })).toBeVisible({ timeout: 20_000 })

  // ...and the files arrive on the other host's filesystem.
  await expect(async () => {
    expect(readFileSync(join(dest, 'bundle', 'app.bin'), 'utf8')).toBe('the binary')
    expect(readFileSync(join(dest, 'bundle', 'conf', 'settings.yaml'), 'utf8')).toBe('key: value')
  }).toPass({ timeout: 30_000 })

  // A copy, not a move.
  expect(readFileSync(join(source, 'bundle', 'app.bin'), 'utf8')).toBe('the binary')
})

test('edits a file in place', async ({ page }) => {
  const dir = here('edit')
  writeFileSync(join(dir, 'motd.conf'), 'welcome to the old text\n')

  await signIn(page)
  await ensureConnection(page, 'Host A', SSH_PORT, 'Test host password')

  await page.getByRole('button', { name: 'Files' }).click()
  const pane = await openPane(page, 'left', 'Host A', dir)

  await row(pane, 'motd.conf').getByRole('button', { name: 'motd.conf', exact: true }).dblclick()

  const editor = page.getByRole('dialog', { name: 'Editing motd.conf' })
  await expect(editor).toBeVisible({ timeout: 20_000 })

  const text = editor.getByLabel('Contents of motd.conf')
  await expect(text).toHaveValue('welcome to the old text\n', { timeout: 20_000 })

  await text.fill('welcome to the new text\n')
  await editor.getByRole('button', { name: 'Save' }).click()

  await expect(async () => {
    expect(readFileSync(join(dir, 'motd.conf'), 'utf8')).toBe('welcome to the new text\n')
  }).toPass({ timeout: 20_000 })

  await editor.getByRole('button', { name: 'Close' }).click()
  await expect(editor).toBeHidden()
})

test('creates, renames, chmods and deletes', async ({ page }) => {
  const dir = here('mutate')
  writeFileSync(join(dir, 'before.sh'), '#!/bin/sh\n')

  await signIn(page)
  await ensureConnection(page, 'Host A', SSH_PORT, 'Test host password')

  await page.getByRole('button', { name: 'Files' }).click()
  const pane = await openPane(page, 'left', 'Host A', dir)

  await test.step('new folder', async () => {
    page.once('dialog', (d) => void d.accept('made-here'))
    await pane.getByRole('button', { name: 'New folder' }).click()

    await expect(row(pane, 'made-here')).toBeVisible({ timeout: 20_000 })
    expect(existsSync(join(dir, 'made-here'))).toBe(true)
  })

  await test.step('rename', async () => {
    const target = row(pane, 'before.sh')
    await target.hover()

    page.once('dialog', (d) => void d.accept('after.sh'))
    await target.getByRole('button', { name: 'Rename' }).click()

    await expect(row(pane, 'after.sh')).toBeVisible({ timeout: 20_000 })
    expect(existsSync(join(dir, 'before.sh'))).toBe(false)
    expect(existsSync(join(dir, 'after.sh'))).toBe(true)
  })

  await test.step('chmod', async () => {
    const target = row(pane, 'after.sh')
    await target.hover()

    page.once('dialog', (d) => void d.accept('0750'))
    await target.getByRole('button', { name: 'Mode' }).click()

    await expect(row(pane, 'after.sh')).toContainText('rwxr-x---', { timeout: 20_000 })
  })

  await test.step('delete', async () => {
    const target = row(pane, 'after.sh')
    await target.hover()

    page.once('dialog', (d) => void d.accept())
    await target.getByRole('button', { name: 'Delete' }).click()

    await expect(row(pane, 'after.sh')).toHaveCount(0, { timeout: 20_000 })
    expect(existsSync(join(dir, 'after.sh'))).toBe(false)
  })
})
