import { test, expect, type Page } from '@playwright/test'
import {
  chooseCredential, closeWindow, connectTo, editorCategory, ensurePasswordCredential,
  hasConnection, openNewConnection, openPage, paneMenu, run, saveNewConnection,
  screenText, signIn as signInWith, treeRow, typeLine, type Pane,
} from './ui'

// The things a network team does with a terminal that a terminal alone does
// not do: colour what matters, send a command they have typed a hundred
// times, put one keyboard onto a rack, and know when their work is being
// written to disk.
//
// These are exactly the features no Go test can finish proving. Highlighting
// is drawn by the renderer into a canvas; a snippet is sent from a popover;
// broadcast is a group set from a browser and the proof of it is two screens
// showing the same thing. All four end in the browser, so they are tested in
// one.

const EMAIL = 'power@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const SSH_HOST = process.env.BKD_E2E_SSH_HOST ?? '127.0.0.1'
const SSH_PORT = process.env.BKD_E2E_SSH_PORT ?? ''
const SSH_USER = process.env.BKD_E2E_SSH_USER ?? 'tester'
const SSH_PASSWORD = process.env.BKD_E2E_SSH_PASSWORD ?? ''

interface DrawnSpan {
  rule: string
  colour: string
  text: string
}

declare global {
  interface Window {
    bkdTerminalHighlights?: (key: string) => DrawnSpan[] | null
  }
}

test.skip(!SSH_PORT, 'no test SSH server; run through scripts/e2e.sh')
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

/** Options a connection may be created with, beyond where it points. */
interface ConnectionExtras {
  /** A highlight rule, added through the watch-rules editor. */
  highlight?: { name: string; pattern: string; colour: string }
  /** Turn on the server-side transcript. */
  record?: boolean
}

/**
 * ensureConnection saves a connection, with whatever extras it asks for.
 *
 * Written so any test here can be run alone with --grep: it checks for the
 * connection first rather than assuming an earlier test created it.
 */
async function ensureConnection(
  page: Page, name: string, credentialName: string, extras: ConnectionExtras = {},
) {
  await ensurePasswordCredential(page, credentialName, SSH_USER, SSH_PASSWORD)

  if (await hasConnection(page, name)) return

  const form = await openNewConnection(page)

  await form.getByLabel('Name', { exact: true }).fill(name)
  await form.getByLabel('Hostname or address', { exact: true }).fill(SSH_HOST)
  await form.getByLabel('Port', { exact: true }).fill(SSH_PORT)
  await form.getByLabel('Username on the remote host', { exact: true }).fill(SSH_USER)
  await chooseCredential(form, credentialName)

  if (extras.highlight) {
    // The editor opens the rules itself on this category; a click on their
    // heading would fold them away again, so only open them if they are not.
    await editorCategory(form, 'Watch rules')
    const rules = form.locator('details.triggers')
    if (!(await rules.evaluate((el) => (el as HTMLDetailsElement).open))) {
      await rules.locator('summary').click()
    }
    await form.getByRole('button', { name: 'Add a rule' }).click()

    // Scoped to the rule's own box: the connection form has a "Name" field
    // of its own, and an unscoped label would find whichever came first.
    const rule = form.locator('fieldset.trigger').first()
    await rule.getByLabel('Name', { exact: true }).fill(extras.highlight.name)
    await rule.getByLabel('When the output matches').fill(extras.highlight.pattern)
    await rule.getByRole('combobox', { name: 'Then' }).selectOption('highlight')
    await rule.getByRole('combobox', { name: 'Colour' }).selectOption(extras.highlight.colour)
  }

  if (extras.record) {
    await editorCategory(form, 'Log file')
    await form.getByLabel('Write a transcript of this session to the server').check()
  }

  await saveNewConnection(form)
  await expect(treeRow(page, name)).toBeVisible()
}

/**
 * connect opens a terminal and returns a locator bound to that pane.
 *
 * Bound by key rather than by `.last()`, which matters here and nowhere else
 * in the suite: these tests open two panes at once, and a `.last()` locator
 * is lazy — the handle for the first pane would quietly start resolving to
 * the second the moment it appeared, and a broadcast test would then compare
 * a screen with itself and pass regardless. connectTo binds by key.
 *
 * Opened from the Session Manager's row rather than from a tab: once a tab is
 * open its label is a button with the same name, and these tests open the
 * same connection twice on purpose.
 */
async function connect(page: Page, name: string): Promise<Pane> {
  return connectTo(page, name)
}

async function paneKey(pane: Pane): Promise<string> {
  const key = await pane.getAttribute('data-pane-key')
  expect(key, 'the pane carries no key').toBeTruthy()
  return key!
}

async function highlights(page: Page, pane: Pane): Promise<DrawnSpan[]> {
  const key = await paneKey(pane)
  const spans = await page.evaluate((k) => window.bkdTerminalHighlights?.(k) ?? null, key)
  expect(spans, 'the highlighter is not registered').not.toBeNull()
  return spans!
}

test('a highlight rule colours what the device printed', async ({ page }) => {
  await signIn(page)
  await ensureConnection(page, 'Highlight host', 'Power password', {
    // (?i) is RE2's inline case-insensitive flag and a syntax error in
    // JavaScript, so a rule written the way Go documents it is exactly the
    // one that would silently never match. Deliberately used here.
    highlight: { name: 'interfaces down', pattern: '(?i)interface .* down', colour: 'red' },
  })

  const pane = await connect(page, 'Highlight host')

  await run(page, pane, 'echo Interface Gi1/0/7 is DOWN', /Gi1\/0\/7 is DOWN/)

  await expect(async () => {
    const spans = await highlights(page, pane)
    const marked = spans.find((span) => span.text.includes('Gi1/0/7'))
    expect(marked, `nothing was highlighted; drawn: ${JSON.stringify(spans)}`).toBeTruthy()
    expect(marked!.rule).toBe('interfaces down')
    expect(marked!.colour).toBe('red')
  }).toPass({ timeout: 20_000 })
})

test('a snippet is sent to the terminal, asking for what changes', async ({ page }) => {
  await signIn(page)

  const library = await openPage(page, 'snippets')
  await expect(library.getByRole('heading', { name: 'Snippets', exact: true })).toBeVisible()

  if (!(await library.getByText('describe a port', { exact: true }).count())) {
    await library.getByRole('button', { name: 'New snippet' }).click()
    await library.getByLabel('Name', { exact: true }).fill('describe a port')
    await library.getByLabel('Command', { exact: true }).fill('echo port-{{port}}-marked')
    await library.getByRole('button', { name: 'Create snippet' }).click()
    await expect(library.getByRole('heading', { name: 'New snippet' })).toBeHidden()
  }
  await closeWindow(library)

  await ensureConnection(page, 'Snippet host', 'Power password')
  const pane = await connect(page, 'Snippet host')

  await paneMenu(pane, 'Send a snippet…')
  const menu = pane.getByRole('dialog', { name: 'Send a snippet' })
  await menu.getByRole('button', { name: 'describe a port' }).click()

  // The placeholder became a question rather than being stored, which is the
  // whole reason the syntax exists.
  await menu.getByLabel('port', { exact: true }).fill('Gi1/0/24')
  await menu.getByRole('button', { name: 'Send', exact: true }).click()

  await expect(async () => {
    expect(await screenText(page, pane)).toMatch(/port-Gi1\/0\/24-marked/)
  }).toPass({ timeout: 20_000 })
})

test('one keyboard reaches two terminals', async ({ page }) => {
  await signIn(page)

  // Two distinct connections, which is what a rack is. Terminals left running
  // by the earlier tests in this file are still open on the server — that is
  // session survival working — so the group is chosen by name rather than
  // with "select all", which would sweep them in too.
  await ensureConnection(page, 'Broadcast one', 'Power password')
  await ensureConnection(page, 'Broadcast two', 'Power password')

  const first = await connect(page, 'Broadcast one')
  const second = await connect(page, 'Broadcast two')

  await paneMenu(second, 'Broadcast to other terminals…')
  const menu = second.getByRole('dialog', { name: 'Broadcast to other terminals' })
  await expect(menu.getByTestId('broadcast-candidates')).toBeVisible()
  // Clicked and then asserted rather than .check()ed, because the tick
  // follows the server's answer instead of leading it: the group is set on
  // the server, and showing one it refused would be a lie about where the
  // keys are going. .check() verifies the box the instant it clicks, before
  // the acknowledgement has come back.
  const box = menu
    .getByTestId('broadcast-candidates')
    .locator('li')
    .filter({ hasText: 'Broadcast one' })
    .getByRole('checkbox')
  await box.click()
  await expect(box).toBeChecked()

  await menu.getByRole('button', { name: 'Close' }).click()

  // The pane says how many terminals its keyboard reaches. Somebody about to
  // type into a rack has to be able to see that they are.
  await expect(second.getByTestId('broadcast-badge')).toContainText('typing into 2')

  await typeLine(page, second, 'echo reached-both-of-them')

  await expect(async () => {
    expect(await screenText(page, second)).toMatch(/reached-both-of-them/)
    expect(await screenText(page, first)).toMatch(/reached-both-of-them/)
  }).toPass({ timeout: 20_000 })

  // And leaving the group stops it, which matters more than joining it.
  await paneMenu(second, 'Broadcast to other terminals…')
  await menu.getByRole('button', { name: 'Clear' }).click()
  await menu.getByRole('button', { name: 'Close' }).click()
  await expect(second.getByTestId('broadcast-badge')).toBeHidden()

  await typeLine(page, second, 'echo only-the-one-i-typed-at')

  await expect(async () => {
    expect(await screenText(page, second)).toMatch(/only-the-one-i-typed-at/)
  }).toPass({ timeout: 20_000 })
  expect(await screenText(page, first)).not.toMatch(/only-the-one-i-typed-at/)
})

test('a recorded session says so on the terminal', async ({ page }) => {
  await signIn(page)
  await ensureConnection(page, 'Recorded host', 'Power password', { record: true })

  const pane = await connect(page, 'Recorded host')

  // Said on the terminal itself, not only in a settings page nobody opens.
  await expect(pane.getByText('REC', { exact: true })).toBeVisible({ timeout: 20_000 })
  await expect(pane.getByTestId('pane-notices'))
    .toContainText('being recorded to a transcript')
})
