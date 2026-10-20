import { test, expect, type Page } from '@playwright/test'
import {
  chooseCredential, closeWindow, connectTo, ensurePasswordCredential, hasConnection,
  openNewConnection, openPage, run, saveNewConnection, screenText, settle,
  signIn as signInWith, treeRow, type Pane,
} from './ui'

// The terminal, driven through a real browser against a real SSH server with
// a real pty.
//
// The Go tests already drive the WebSocket bridge against an in-process SSH
// server, which proves the protocol. These prove the other half, which no Go
// test structurally can: that xterm.js, the WebGL renderer, the content
// security policy, the WebSocket upgrade and a genuine shell on a genuine pty
// all work together in the browser people will actually use.

// Its own account: the suites share an instance, and sharing an account
// would mean sharing a vault, a credential list and a known-hosts list with
// whichever spec file happened to run first.
const EMAIL = 'terminal@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const SSH_HOST = process.env.BKD_E2E_SSH_HOST ?? '127.0.0.1'
const SSH_PORT = process.env.BKD_E2E_SSH_PORT ?? ''
const SSH_USER = process.env.BKD_E2E_SSH_USER ?? 'tester'
const SSH_PASSWORD = process.env.BKD_E2E_SSH_PASSWORD ?? ''

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

/** signIn gets the page to the workspace from wherever it starts. */
async function signIn(page: Page) {
  await signInWith(page, { email: EMAIL, password: PASSWORD, passphrase: PASSPHRASE })
}

/**
 * ensureConnection saves a connection pointing at the test SSH server.
 *
 * Every helper in this file is written so a single test can be run alone with
 * `--grep`. Tests that quietly depend on an earlier test's leftovers turn one
 * failure into a cascade and hide which one actually broke.
 */
async function ensureConnection(page: Page, name: string, credentialName: string) {
  await ensurePasswordCredential(page, credentialName, SSH_USER, SSH_PASSWORD)

  if (await hasConnection(page, name)) return

  const editor = await openNewConnection(page)

  await editor.getByLabel('Name', { exact: true }).fill(name)
  await editor.getByLabel('Hostname or address', { exact: true }).fill(SSH_HOST)
  await editor.getByLabel('Port', { exact: true }).fill(SSH_PORT)
  await editor.getByLabel('Username on the remote host', { exact: true }).fill(SSH_USER)
  await chooseCredential(editor, credentialName)

  await saveNewConnection(editor)
  await expect(treeRow(page, name)).toBeVisible()
}

/** connect opens a terminal, accepting the host key on first contact. */
async function connect(page: Page, name: string): Promise<Pane> {
  return connectTo(page, name)
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

  // The server kept the session. Either the tab comes back by itself — the
  // browser remembers its open tabs in localStorage, which a page in the same
  // context shares — or the Session Manager offers it under "Still running".
  // Both are the same promise kept; a person is shown one or the other.
  const tab = second.locator('.tabstrip').getByRole('button', { name: 'Survival host', exact: true })
  const orphan = second.getByRole('button', { name: /^Survival host\b.*reattach$/ })
  await expect(tab.or(orphan).first()).toBeVisible({ timeout: 20_000 })

  if (!(await tab.isVisible())) {
    await orphan.click()
  }

  const revived = second.getByTestId('terminal-pane').last()
  await settle(revived)

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

  const hosts = await openPage(page, 'hosts')

  const row = hosts.getByRole('row').filter({ hasText: `${SSH_HOST}:${SSH_PORT}` })
  await expect(row).toBeVisible()
  await expect(row).toContainText('SHA256:')

  page.once('dialog', (d) => void d.accept())
  await row.getByRole('button', { name: 'Forget' }).click()

  await expect(hosts.getByText('No host keys have been accepted yet.')).toBeVisible()
  await closeWindow(hosts)
})
