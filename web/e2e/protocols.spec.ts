import { test, expect, type Page } from '@playwright/test'

// Telnet, in a real browser, against a device that speaks it.
//
// The Go tests already drive the protocol against a peer under their control
// and the whole stack against a device that validates a credential. What
// these add is the part no Go test can reach: that the connection form knows
// telnet from SSH, that the logon sequence a person never configured types
// the stored password at the device's prompt, and that the plaintext nature
// of the thing is on screen rather than only in an audit record.

const BASE = process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500'

const EMAIL = 'protocols@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const HOST = process.env.BKD_E2E_SSH_HOST ?? '127.0.0.1'
const TELNET_PORT = process.env.BKD_E2E_TELNET_PORT ?? ''
const SSH_USER = process.env.BKD_E2E_SSH_USER ?? 'tester'
const SSH_PASSWORD = process.env.BKD_E2E_SSH_PASSWORD ?? ''

declare global {
  interface Window {
    bkdTerminalText?: (key: string) => string | null
  }
}

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
  await page.goto(BASE)

  const workspace = page.getByRole('button', { name: 'Terminal' })
  const signInButton = page.getByRole('button', { name: 'Sign in' })
  const enrol = page.getByRole('heading', { name: 'Set up your vault' })
  const unlock = page.getByRole('heading', { name: 'Unlock your vault' })

  await expect(workspace.or(signInButton).or(enrol).or(unlock)).toBeVisible()

  if (await signInButton.isVisible()) {
    await page.getByLabel('Email address', { exact: true }).fill(EMAIL)
    await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
    await signInButton.click()
    await expect(workspace.or(enrol).or(unlock)).toBeVisible()
  }

  if (await enrol.isVisible()) {
    await page.getByLabel('Choose a passphrase', { exact: true }).fill(PASSPHRASE)
    await page.getByLabel('Repeat it', { exact: true }).fill(PASSPHRASE)
    await page.getByRole('button', { name: 'Create vault' }).click()
  } else if (await unlock.isVisible()) {
    await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE)
    await page.getByRole('button', { name: 'Unlock' }).click()
  }

  await expect(workspace).toHaveAttribute('aria-current', 'page')
}

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

/** ensureTelnetConnection saves a telnet connection through the form. */
async function ensureTelnetConnection(page: Page, name: string, credentialName: string) {
  await ensureCredential(page, credentialName)

  await page.getByRole('button', { name: 'Terminal' }).click()
  if (await page.getByRole('button', { name, exact: true }).count()) return

  await page.getByRole('button', { name: 'New connection', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'New connection' })).toBeVisible()

  await page.getByLabel('Name', { exact: true }).fill(name)
  await page.getByRole('combobox', { name: 'Protocol' }).selectOption('telnet')

  // Choosing telnet says what it costs, before anything is saved.
  await expect(page.getByText(/in the clear/)).toBeVisible()

  await page.getByLabel('Hostname or address', { exact: true }).fill(HOST)
  await page.getByLabel('Port', { exact: true }).fill(TELNET_PORT)
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

type Pane = ReturnType<Page['getByTestId']>

async function screenText(page: Page, pane: Pane): Promise<string> {
  const key = await pane.getAttribute('data-pane-key')
  expect(key, 'the pane carries no key').toBeTruthy()
  const text = await page.evaluate((k) => window.bkdTerminalText?.(k) ?? null, key!)
  expect(text, 'the terminal is not registered').not.toBeNull()
  return text!
}

async function waitForScreen(page: Page, pane: Pane, marker: RegExp) {
  await expect(async () => {
    expect(await screenText(page, pane)).toMatch(marker)
  }).toPass({ timeout: 30_000 })
}

test('a telnet connection logs itself in and reaches a prompt', async ({ page }) => {
  await signIn(page)
  await ensureTelnetConnection(page, 'Old switch', 'Switch login')

  await page.getByRole('button', { name: 'Old switch', exact: true }).click()

  // The panel says what this connection is, and that it is not protected.
  const selection = page.locator('.selection')
  await expect(selection).toContainText('telnet')
  await expect(selection.getByText('not encrypted')).toBeVisible()

  await selection.getByRole('button', { name: 'Connect' }).click()

  const pane = page.getByTestId('terminal-pane').last()

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
  await page.getByRole('button', { name: 'Terminal' }).click()

  await page.getByRole('button', { name: 'Console server', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Add a console server' })).toBeVisible()

  await page.getByLabel('Address', { exact: true }).fill('console-01.example.com')
  await page.getByLabel('Lines', { exact: true }).fill('12')

  await page.getByRole('button', { name: 'Preview', exact: true }).click()

  // Every port is shown before anything is written. Forty-eight connections
  // from a base port that was right for the last rack is a mistake to catch
  // here rather than during an outage.
  await expect(page.getByText('12 connections would be created')).toBeVisible()
  await expect(page.getByText('console-01.example.com:3001')).toBeVisible()
  await expect(page.getByText('console-01.example.com:3012')).toBeVisible()

  // Padded, so the tree sorts like the rack rather than putting line 10
  // between line 1 and line 2.
  await expect(page.getByText('console-01.example.com line 01')).toBeVisible()

  await page.getByRole('button', { name: 'Create 12 connections' }).click()

  await expect(page.getByRole('button', { name: 'console-01.example.com line 01', exact: true }))
    .toBeVisible({ timeout: 20_000 })
  await expect(page.getByRole('button', { name: 'console-01.example.com line 12', exact: true }))
    .toBeVisible()
})
