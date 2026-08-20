import { test, expect, type Page } from '@playwright/test'

// The terminal, driven through a real browser against a real SSH server with
// a real pty.
//
// The Go tests already drive the WebSocket bridge against an in-process SSH
// server, which proves the protocol. These prove the other half, which no Go
// test structurally can: that xterm.js, the WebGL renderer, the content
// security policy, the WebSocket upgrade and a genuine shell on a genuine pty
// all work together in the browser people will actually use.

const BASE = process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500'
const EMAIL = 'admin@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const SSH_HOST = process.env.BKD_E2E_SSH_HOST ?? '127.0.0.1'
const SSH_PORT = process.env.BKD_E2E_SSH_PORT ?? ''
const SSH_USER = process.env.BKD_E2E_SSH_USER ?? 'tester'
const SSH_PASSWORD = process.env.BKD_E2E_SSH_PASSWORD ?? ''

declare global {
  interface Window {
    /** The app's test seam; see web/src/terminal/screen.ts. */
    bkdTerminalText?: (key: string) => string | null
  }
}

test.skip(!SSH_PORT, 'no test SSH server; run through scripts/e2e.sh')

test.beforeEach(async ({ page }) => {
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return
    const text = msg.text()
    // The browser logs an error for every non-2xx fetch, and the app makes
    // one legitimately: the whoami check before signing in. Everything else
    // — a CSP violation above all — must fail the test.
    if (text.startsWith('Failed to load resource')) return
    throw new Error(`console error: ${text}`)
  })
  page.on('pageerror', (err) => {
    throw new Error(`page error: ${err.message}`)
  })
})

/**
 * signIn gets the page to the workspace from wherever it starts.
 *
 * A second tab in the same browser inherits the session cookie, so it may
 * arrive already signed in with the vault still open — which is exactly the
 * case the survival test needs. Rather than assume a starting state, this
 * looks at what is on screen and does only what is missing.
 */
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

/**
 * ensureCredential stores the test host's password, if it is not there yet.
 *
 * Every helper in this file is written so a single test can be run alone with
 * `--grep`. Tests that quietly depend on an earlier test's leftovers turn one
 * failure into a cascade and hide which one actually broke.
 */
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

/** ensureConnection saves a connection pointing at the test SSH server. */
async function ensureConnection(page: Page, name: string, credentialName: string) {
  await ensureCredential(page, credentialName)

  await page.getByRole('button', { name: 'Terminal' }).click()
  if (await page.getByRole('button', { name, exact: true }).count()) return

  await page.getByRole('button', { name: 'New connection', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'New connection' })).toBeVisible()

  await page.getByLabel('Name', { exact: true }).fill(name)
  await page.getByLabel('Hostname or address', { exact: true }).fill(SSH_HOST)
  await page.getByLabel('Port', { exact: true }).fill(SSH_PORT)
  await page.getByLabel('Username on the remote host', { exact: true }).fill(SSH_USER)
  // By role, not by label: the select sits inside its <label>, so the label's
  // text includes every option and no exact label match is possible.
  //
  // Options are labelled "<name> · <kind>" and carry the credential's ID as
  // their value, which the test has no other way to learn. A collapsed select
  // renders no text, so its options are read from the DOM rather than matched
  // with a text locator.
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

/** connect opens a terminal, accepting the host key on first contact. */
async function connect(page: Page, name: string) {
  await page.getByRole('button', { name, exact: true }).click()
  // Scoped to the selection panel: the tree row carries a Connect button too,
  // and it is hidden until the row is hovered.
  await page.locator('.selection').getByRole('button', { name: 'Connect' }).click()

  const pane = page.getByTestId('terminal-pane').last()

  // A host we have not seen before asks first. Accept only after the
  // fingerprint has actually rendered — a dialog that appears without one
  // would be the failure this check exists to catch.
  const prompt = pane.getByRole('alertdialog', { name: 'Unrecognised host key' })
  if (await prompt.isVisible().catch(() => false)) {
    await expect(pane.getByTestId('host-key-fingerprint')).toContainText('SHA256:')
    await pane.getByRole('button', { name: /fingerprint matches/ }).click()
  }

  await expect(pane.getByText('Connected', { exact: true })).toBeVisible({ timeout: 20_000 })
  return pane
}

type Pane = ReturnType<Page['getByTestId']>

/**
 * screenText is what the terminal is showing, scrollback included.
 *
 * Read through the seam the app exposes rather than from the DOM: xterm's
 * WebGL renderer draws to a canvas, so there is no element whose text a test
 * could query.
 */
async function screenText(page: Page, pane: Pane): Promise<string> {
  const key = await pane.getAttribute('data-pane-key')
  expect(key, 'the pane carries no key').toBeTruthy()

  const text = await page.evaluate((k) => window.bkdTerminalText?.(k) ?? null, key!)
  expect(text, 'the terminal is not registered').not.toBeNull()
  return text!
}

/** run types a command and waits for something it prints. */
async function run(page: Page, pane: Pane, command: string, marker: RegExp) {
  await pane.locator('.xterm-helper-textarea').first().focus()
  await page.keyboard.type(command)
  await page.keyboard.press('Enter')

  await expect(async () => {
    expect(await screenText(page, pane)).toMatch(marker)
  }).toPass({ timeout: 20_000 })
}

test('connects to a real host and runs a command', async ({ page }) => {
  await signIn(page)
  await ensureConnection(page, 'Test host', 'Test host password')

  const pane = await connect(page, 'Test host')

  await run(page, pane, `echo hello-from-$((6*7))`, /hello-from-42/)
})

test('a resized window reaches the remote pty', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 })
  await signIn(page)
  await ensureConnection(page, 'Test host', 'Test host password')

  const pane = await connect(page, 'Test host')

  // `stty size` reads the kernel's idea of the pty dimensions on the far
  // side. If it answers at all, the resize travelled the whole way: browser
  // to WebSocket to SSH window-change to the pty.
  await run(page, pane, 'stty size', /\d+ \d+/)

  await page.setViewportSize({ width: 900, height: 620 })
  await run(page, pane, 'stty size', /\d+ \d+/)

  await expect(async () => {
    const matches = [...(await screenText(page, pane)).matchAll(/^(\d+) (\d+)$/gm)]
    expect(matches.length).toBeGreaterThanOrEqual(2)
    const first = matches[matches.length - 2]!
    const second = matches[matches.length - 1]!
    expect(second[2]).not.toBe(first[2])
  }).toPass({ timeout: 20_000 })
})

test('the session survives losing the browser', async ({ page, context }) => {
  await signIn(page)

  // Its own connection, so the terminal it leaves running is identifiable by
  // name. Earlier tests deliberately abandon theirs — that is what proves
  // survival — and every one of them would otherwise be called "Test host".
  await ensureConnection(page, 'Survival host', 'Test host password')

  const pane = await connect(page, 'Survival host')

  // Leave a mark in the shell's history that proves, on return, that this is
  // the same process rather than a fresh login.
  await run(page, pane, 'MARKER=survived-the-drop; echo $MARKER', /survived-the-drop/)

  // Close the page outright: no clean WebSocket close, no chance to tidy up.
  // This is a laptop lid closing, not a user clicking away.
  await page.close()

  const second = await context.newPage()
  await signIn(second)

  // The server kept the session, and says so.
  await expect(second.getByRole('heading', { name: 'Still running' })).toBeVisible({
    timeout: 20_000,
  })
  await second.getByRole('button', { name: /^Survival host\b.*reattach$/ }).click()

  const revived = second.getByTestId('terminal-pane').last()
  await expect(revived.getByText('Connected', { exact: true })).toBeVisible({ timeout: 20_000 })

  // The replayed scrollback carries what was on screen before the drop...
  await expect(async () => {
    expect(await screenText(second, revived)).toContain('survived-the-drop')
  }).toPass({ timeout: 20_000 })

  // ...and the shell is the same process, because it still holds the variable.
  await run(second, revived, 'echo "still=$MARKER"', /still=survived-the-drop/)
})

test('the accepted host key is listed and can be forgotten', async ({ page }) => {
  await signIn(page)
  await ensureConnection(page, 'Test host', 'Test host password')
  await connect(page, 'Test host')

  await page.getByRole('button', { name: 'Known hosts' }).click()
  await expect(page.getByRole('heading', { name: 'Known hosts' })).toBeVisible()

  const row = page.getByRole('row').filter({ hasText: `${SSH_HOST}:${SSH_PORT}` })
  await expect(row).toBeVisible()
  await expect(row).toContainText('SHA256:')

  page.once('dialog', (d) => void d.accept())
  await row.getByRole('button', { name: 'Forget' }).click()

  await expect(page.getByText('No host keys have been accepted yet.')).toBeVisible()
})
