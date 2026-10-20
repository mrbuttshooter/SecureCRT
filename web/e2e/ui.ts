import { expect, type Locator, type Page } from '@playwright/test'

// What every spec needs to know about how the signed-in app is laid out, in
// one place, so that the next restructure of the interface is one edit here
// rather than seven.
//
// The signed-in app is one main window: a menu bar, a toolbar, the Session
// Manager down the left, tabs and terminals on the right and a status bar
// underneath. Everything that used to be a page (credentials, known hosts, the
// file browser, import and export...) opens from a menu as a modal window over
// it, and closes again with its X or Escape. Nothing here is a top-level
// navigation any more, which is why there is no "go to the Credentials tab":
// there is only "open the Credentials window, do the thing, close it".

export const BASE = process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500'

export interface Account {
  email: string
  password: string
  passphrase: string
}

/** A locator bound to one terminal pane (see openTerminal). */
export type Pane = Locator

// --- signing in -------------------------------------------------------------

/**
 * signedInMarker is what "the workspace is on screen" looks like: the menu
 * bar only exists in the signed-in, vault-open main window.
 */
export function signedInMarker(page: Page): Locator {
  return page.getByRole('menubar')
}

/** signedIn asserts the page has reached the workspace. */
export async function signedIn(page: Page) {
  await expect(signedInMarker(page)).toBeVisible()
}

/**
 * signIn gets the page to the workspace from wherever it starts.
 *
 * A second page in the same browser context inherits the session cookie, so
 * it may arrive already signed in with the vault still open. Rather than
 * assume a starting state, this looks at what is on screen and does only what
 * is missing, so any single test can be run alone with `--grep`.
 */
export async function signIn(page: Page, account: Account) {
  await page.goto(BASE)

  const workspace = signedInMarker(page)
  const signInButton = page.getByRole('button', { name: 'Sign in' })
  const enrol = page.getByRole('heading', { name: 'Set up your vault' })
  const unlock = page.getByRole('heading', { name: 'Unlock your vault' })

  await expect(workspace.or(signInButton).or(enrol).or(unlock)).toBeVisible()

  if (await signInButton.isVisible()) {
    await page.getByLabel('Email address', { exact: true }).fill(account.email)
    await page.getByLabel('Password', { exact: true }).fill(account.password)
    await signInButton.click()
    await expect(workspace.or(enrol).or(unlock)).toBeVisible()
  }

  if (await enrol.isVisible()) {
    await page.getByLabel('Choose a passphrase', { exact: true }).fill(account.passphrase)
    await page.getByLabel('Repeat it', { exact: true }).fill(account.passphrase)
    await page.getByRole('button', { name: 'Create vault' }).click()
  } else if (await unlock.isVisible()) {
    await page.getByLabel('Passphrase', { exact: true }).fill(account.passphrase)
    await page.getByRole('button', { name: 'Unlock' }).click()
  }

  await signedIn(page)
}

// --- menus and windows ------------------------------------------------------

/**
 * openMenu opens a menu-bar menu and chooses one entry.
 *
 * The entry text is exactly what the menu shows, ellipsis included
 * ("Known hosts…"). Entries exist only while their menu is open, so the click
 * on the title is what makes them findable. Entries may be plain items, ticks
 * or radios, depending on the entry.
 */
export async function openMenu(page: Page, menu: string, entry: string) {
  const bar = page.getByRole('menubar')
  await bar.getByRole('menuitem', { name: menu, exact: true }).click()

  const dropdown = bar.getByRole('menu')
  await expect(dropdown).toBeVisible()
  await dropdown.getByRole('menuitem', { name: entry, exact: true })
    .or(dropdown.getByRole('menuitemcheckbox', { name: entry, exact: true }))
    .or(dropdown.getByRole('menuitemradio', { name: entry, exact: true }))
    .click()
}

/** The windows that open over the workspace, by the name specs give them. */
export type PageName =
  | 'credentials' | 'hosts' | 'snippets' | 'recordings' | 'tunnels' | 'files'
  | 'transfer' | 'security' | 'sessions' | 'admin'

const PAGES: Record<PageName, { menu: string; entry: string; title: string }> = {
  credentials: { menu: 'Tools', entry: 'Credentials: keys and passwords…', title: 'Credentials: keys and passwords' },
  hosts: { menu: 'Tools', entry: 'Known hosts…', title: 'Known hosts' },
  snippets: { menu: 'Tools', entry: 'Snippets and button bar…', title: 'Snippets and button bar' },
  recordings: { menu: 'Tools', entry: 'Transcripts…', title: 'Transcripts' },
  tunnels: { menu: 'Tools', entry: 'Port forwarding and tunnels…', title: 'Port forwarding and tunnels' },
  files: { menu: 'Transfer', entry: 'File transfer (SFTP)…', title: 'File transfer (SFTP)' },
  transfer: { menu: 'File', entry: 'Import and export…', title: 'Import and export' },
  security: { menu: 'Help', entry: 'Security and two-factor…', title: 'Security and two-factor' },
  sessions: { menu: 'Help', entry: 'Sign-ins…', title: 'Sign-ins' },
  admin: { menu: 'Help', entry: 'Administration…', title: 'Administration' },
}

/** windowTitled finds a modal window by its title. */
export function windowTitled(page: Page, title: string): Locator {
  return page.getByRole('dialog', { name: title, exact: true })
}

/**
 * openPage opens one of the windows that used to be a page, and returns the
 * window so the caller can scope everything inside it.
 *
 * Scoping to the returned window matters now that the workspace stays mounted
 * behind it: an unscoped `page.getByLabel('Name')` would also look at the
 * main window's controls.
 *
 * The window's title is an <h2> too, so for a page whose own heading has the
 * same text (Known hosts, Transcripts) a heading query inside the window finds
 * two; the window's own visibility is the assertion that the page opened.
 */
export async function openPage(page: Page, which: PageName): Promise<Locator> {
  const { menu, entry, title } = PAGES[which]
  await openMenu(page, menu, entry)

  const win = windowTitled(page, title)
  await expect(win).toBeVisible()
  return win
}

/** closeWindow closes a modal window with its X and waits for it to go. */
export async function closeWindow(win: Locator) {
  await win.locator('.window-close').click()
  await expect(win).toBeHidden()
}

// --- the Session Manager ----------------------------------------------------

function exactly(text: string): RegExp {
  return new RegExp('^' + text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$')
}

/**
 * treeRow finds a saved connection in the Session Manager by its name.
 *
 * Not by role and accessible name: a connection with a live terminal is
 * announced as "<name> (connected)", so an exact name match would stop
 * finding the very row a test has just connected.
 */
export function treeRow(page: Page, name: string): Locator {
  return page.locator('.sidebar .tree-label').filter({
    has: page.locator('.tree-name', { hasText: exactly(name) }),
  })
}

/**
 * savedConnectionNames reads the names the server holds.
 *
 * Used by the ensure* helpers to decide whether a connection still has to be
 * created. Asking the API rather than looking at the tree avoids a race the
 * tree cannot avoid: right after sign-in it is empty because it has not
 * loaded yet, which looks exactly like a tree with nothing in it. Nothing is
 * written this way; creating connections still goes through the editor.
 */
export async function savedConnectionNames(page: Page): Promise<string[]> {
  const res = await page.request.get(new URL('/api/tree', BASE).toString())
  expect(res.ok(), 'the tree could not be read').toBe(true)
  const tree = (await res.json()) as { sessions?: Array<{ name: string }> }
  return (tree.sessions ?? []).map((s) => s.name)
}

export async function hasConnection(page: Page, name: string): Promise<boolean> {
  return (await savedConnectionNames(page)).includes(name)
}

/** openNewConnection opens the editor for a new connection, from the Session Manager. */
export async function openNewConnection(page: Page): Promise<Locator> {
  await page.locator('.sidebar').getByRole('button', { name: 'New connection', exact: true }).click()
  const win = windowTitled(page, 'New connection')
  await expect(win).toBeVisible()
  return win
}

/**
 * chooseCredential picks a credential in the connection editor.
 *
 * Options are labelled "<name> · <kind>" and carry the credential's ID as
 * their value, which the test has no other way to learn. A collapsed select
 * renders no text, so its options are read from the DOM rather than matched
 * with a text locator. By role, not by label: the select sits inside its
 * <label>, so the label's text includes every option.
 */
export async function chooseCredential(editor: Locator, credentialName: string) {
  const field = editor.getByRole('combobox', { name: 'Credential' })
  const value = await field.evaluate(
    (el, wanted) =>
      Array.from((el as HTMLSelectElement).options)
        .find((option) => option.text.startsWith(wanted))?.value ?? '',
    credentialName,
  )
  expect(value, `no option for the credential "${credentialName}"`).toBeTruthy()
  await field.selectOption(value)
}

/** editorCategory switches the connection editor to one of its categories. */
export async function editorCategory(editor: Locator, category: string) {
  const tab = editor.getByRole('tab', { name: category, exact: true })
  await tab.click()
  await expect(tab).toHaveAttribute('aria-selected', 'true')
}

/** saveNewConnection saves without connecting, and waits for the editor to go. */
export async function saveNewConnection(editor: Locator) {
  await editor.getByRole('button', { name: 'Create only' }).click()
  await expect(editor).toBeHidden()
}

/**
 * ensurePasswordCredential stores a password in the vault if it is not there
 * yet, through the Credentials window, and closes the window again.
 *
 * Every helper here is written so a single test can be run alone with
 * `--grep`: tests that quietly depend on an earlier test's leftovers turn one
 * failure into a cascade and hide which one actually broke.
 */
export async function ensurePasswordCredential(
  page: Page, name: string, username: string, secret: string,
) {
  const win = await openPage(page, 'credentials')
  // The page's own heading only renders once the list has loaded, so waiting
  // for it is what makes the count below mean "not there" rather than "not
  // here yet". Exact, because the window's title starts with the same word.
  await expect(win.getByRole('heading', { name: 'Credentials', exact: true })).toBeVisible()

  if ((await win.getByText(name, { exact: true }).count()) === 0) {
    await win.getByRole('button', { name: 'Add password' }).click()
    await win.getByLabel('Name', { exact: true }).fill(name)
    await win.getByLabel('Username (optional)', { exact: true }).fill(username)
    await win.getByLabel('Secret', { exact: true }).fill(secret)
    await win.getByRole('button', { name: 'Save', exact: true }).click()

    await expect(win.getByText(name, { exact: true }).first()).toBeVisible()
  }

  await closeWindow(win)
}

// --- terminals --------------------------------------------------------------

/**
 * openTerminal opens a terminal on a saved connection by double-clicking its
 * row, and returns a locator bound to that pane.
 *
 * Bound by key rather than by `.last()`: a `.last()` locator is lazy, so the
 * handle for the first of two panes would quietly start resolving to the
 * second the moment it appeared, and a test comparing two screens would
 * compare one with itself and pass regardless.
 */
export async function openTerminal(page: Page, name: string): Promise<Pane> {
  const panes = page.getByTestId('terminal-pane')
  const before = await panes.count()

  await treeRow(page, name).dblclick()

  await expect(panes).toHaveCount(before + 1)
  const key = await panes.last().getAttribute('data-pane-key')
  expect(key, 'the pane carries no key').toBeTruthy()
  return page.locator(`[data-testid="terminal-pane"][data-pane-key="${key}"]`)
}

/** waitLive waits for a pane to be connected. */
export async function waitLive(pane: Pane, timeout = 20_000) {
  // The state is an attribute because a single terminal's own header is
  // hidden while it is live; the status bar says "Ready" for the active one.
  await expect(pane).toHaveAttribute('data-state', 'live', { timeout })
}

/** acceptHostKey answers a pending host key prompt, if there is one. */
export async function acceptHostKey(pane: Pane) {
  const prompt = pane.getByRole('alertdialog', { name: 'Unrecognised host key' })
  if (!(await prompt.isVisible())) return false

  // Accept only after the fingerprint has actually rendered — a dialog that
  // appears without one would be the failure this check exists to catch.
  await expect(pane.getByTestId('host-key-fingerprint')).toContainText('SHA256:')
  await pane.getByRole('button', { name: /fingerprint matches/ }).click()
  return true
}

/**
 * connectTo opens a terminal on a saved connection and waits until it is
 * connected, accepting the host key on first contact.
 *
 * A race between "connected" and "asked about the key" rather than a single
 * look: the first connection to a host asks, later ones do not, and checking
 * for a dialog that has not been drawn yet is how this becomes intermittent.
 */
export async function connectTo(page: Page, name: string, timeout = 20_000): Promise<Pane> {
  const pane = await openTerminal(page, name)
  await settle(pane, timeout)
  return pane
}

/** settle answers a host key prompt if one comes, then waits for live. */
export async function settle(pane: Pane, timeout = 20_000) {
  const prompt = pane.getByRole('alertdialog', { name: 'Unrecognised host key' })
  await expect(async () => {
    const state = await pane.getAttribute('data-state')
    expect(state === 'live' || (await prompt.isVisible()),
      `the pane is ${state}: neither connected nor asking about a host key`).toBe(true)
  }).toPass({ timeout })

  await acceptHostKey(pane)
  await waitLive(pane, timeout)
}

/**
 * paneMenu chooses an entry from a pane's "More terminal actions" menu.
 *
 * The pane's header, and the ⋯ button in it, is hidden while a single
 * terminal is live, so when the button is not there the same menu is opened
 * the way a person without it would: Shift+right-click on the screen, which
 * always opens the menu even with right-click paste switched on.
 */
export async function paneMenu(pane: Pane, entry: string) {
  const more = pane.getByRole('button', { name: 'More terminal actions' })
  if (await more.isVisible()) {
    await more.click()
  } else {
    await pane.locator('.pane-screen').click({ button: 'right', modifiers: ['Shift'] })
  }
  await pane.getByRole('menuitem', { name: entry, exact: true }).click()
}

/**
 * screenText is what the terminal is showing, scrollback included.
 *
 * Read through the seam the app exposes (web/src/terminal/screen.ts) rather
 * than from the DOM: xterm's WebGL renderer draws to a canvas, so there is no
 * element whose text a test could query.
 */
export async function screenText(page: Page, pane: Pane): Promise<string> {
  const key = await pane.getAttribute('data-pane-key')
  expect(key, 'the pane carries no key').toBeTruthy()

  const text = await page.evaluate(
    (k) => (window as unknown as { bkdTerminalText?: (key: string) => string | null })
      .bkdTerminalText?.(k) ?? null,
    key!,
  )
  expect(text, 'the terminal is not registered').not.toBeNull()
  return text!
}

/** typeLine types a command into a pane and presses Enter. */
export async function typeLine(page: Page, pane: Pane, command: string) {
  await pane.locator('.xterm-helper-textarea').first().focus()
  await page.keyboard.type(command)
  await page.keyboard.press('Enter')
}

/** run types a command and waits for something it prints. */
export async function run(
  page: Page, pane: Pane, command: string, marker: RegExp, timeout = 20_000,
) {
  await typeLine(page, pane, command)
  await expect(async () => {
    expect(await screenText(page, pane)).toMatch(marker)
  }).toPass({ timeout })
}
