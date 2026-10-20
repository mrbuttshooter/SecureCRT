import { test, expect, type Page } from '@playwright/test'
import {
  chooseCredential, ensurePasswordCredential, hasConnection, openNewConnection,
  openTerminal, saveNewConnection, screenText, signIn as signInWith, treeRow,
  type Pane,
} from './ui'

// Telnet, in a real browser, against a device that speaks it.
//
// The Go tests already drive the protocol against a peer under their control
// and the whole stack against a device that validates a credential. What
// these add is the part no Go test can reach: that the connection form knows
// telnet from SSH, that the logon sequence a person never configured types
// the stored password at the device's prompt, and that the plaintext nature
// of the thing is on screen rather than only in an audit record.

const EMAIL = 'protocols@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const HOST = process.env.BKD_E2E_SSH_HOST ?? '127.0.0.1'
const TELNET_PORT = process.env.BKD_E2E_TELNET_PORT ?? ''
const SSH_USER = process.env.BKD_E2E_SSH_USER ?? 'tester'
const SSH_PASSWORD = process.env.BKD_E2E_SSH_PASSWORD ?? ''

test.skip(!TELNET_PORT, 'no test telnet device; run through scripts/e2e.sh')
test.describe.configure({ timeout: 120_000 })

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

/** ensureTelnetConnection saves a telnet connection through the form. */
async function ensureTelnetConnection(page: Page, name: string, credentialName: string) {
  await ensurePasswordCredential(page, credentialName, SSH_USER, SSH_PASSWORD)

  if (await hasConnection(page, name)) return

  const editor = await openNewConnection(page)

  await editor.getByLabel('Name', { exact: true }).fill(name)
  await editor.getByRole('combobox', { name: 'Protocol' }).selectOption('telnet')

  // Choosing telnet says what it costs, before anything is saved.
  await expect(editor.getByText(/in the clear/)).toBeVisible()

  await editor.getByLabel('Hostname or address', { exact: true }).fill(HOST)
  await editor.getByLabel('Port', { exact: true }).fill(TELNET_PORT)
  await editor.getByLabel('Username on the remote host', { exact: true }).fill(SSH_USER)
  await chooseCredential(editor, credentialName)

  await saveNewConnection(editor)
  await expect(treeRow(page, name)).toBeVisible()
}

async function waitForScreen(page: Page, pane: Pane, marker: RegExp) {
  await expect(async () => {
    expect(await screenText(page, pane)).toMatch(marker)
  }).toPass({ timeout: 30_000 })
}

test('a telnet connection logs itself in and reaches a prompt', async ({ page }) => {
  await signIn(page)
  await ensureTelnetConnection(page, 'Old switch', 'Switch login')

  const pane = await openTerminal(page, 'Old switch')

  // The window says what this connection is, and that it is not protected.
  // (The old single-selection panel that said so is gone; the status bar
  // carries the same two facts for the session in front.)
  const status = page.getByRole('group', { name: 'Status', exact: true })
  await expect(status).toContainText('Telnet', { timeout: 20_000 })
  await expect(status).toContainText('Not encrypted', { timeout: 20_000 })

  // No host key dialog: telnet has no host identity, and asking about one
  // would be theatre.
  await expect(pane.getByRole('alertdialog', { name: 'Unrecognised host key' }))
    .toHaveCount(0)

  // Nobody configured a logon sequence. The default one types the stored
  // credential at the device's own prompt, which is what makes an imported
  // telnet tree usable rather than merely present.
  await waitForScreen(page, pane, /testsw>/)

  // The exchange is in the scrollback — an automated login nobody can see is
  // an automated login nobody can check — and the password is not.
  const screen = await screenText(page, pane)
  expect(screen).toMatch(/Username:/)
  expect(screen).toMatch(/Password:/)
  expect(screen).not.toContain(SSH_PASSWORD)

  // And the session works.
  await pane.locator('.xterm-helper-textarea').first().focus()
  await page.keyboard.type('echo through-telnet')
  await page.keyboard.press('Enter')
  await waitForScreen(page, pane, /through-telnet/)
})

test('a console server becomes a folder of lines, previewed first', async ({ page }) => {
  await signIn(page)

  await page.locator('.sidebar').getByRole('button', { name: 'Console server', exact: true }).click()
  const win = page.getByRole('dialog', { name: 'Console server', exact: true })
  await expect(win.getByRole('heading', { name: 'Add a console server' })).toBeVisible()

  await win.getByLabel('Address', { exact: true }).fill('console-01.example.com')
  await win.getByLabel('Lines', { exact: true }).fill('12')

  await win.getByRole('button', { name: 'Preview', exact: true }).click()

  // Every port is shown before anything is written. Forty-eight connections
  // from a base port that was right for the last rack is a mistake to catch
  // here rather than during an outage.
  await expect(win.getByText('12 connections would be created')).toBeVisible()
  await expect(win.getByText('console-01.example.com:3001')).toBeVisible()
  await expect(win.getByText('console-01.example.com:3012')).toBeVisible()

  // Padded, so the tree sorts like the rack rather than putting line 10
  // between line 1 and line 2.
  await expect(win.getByText('console-01.example.com line 01')).toBeVisible()

  await win.getByRole('button', { name: 'Create 12 connections' }).click()

  await expect(treeRow(page, 'console-01.example.com line 01')).toBeVisible({ timeout: 20_000 })
  await expect(treeRow(page, 'console-01.example.com line 12')).toBeVisible()
})
