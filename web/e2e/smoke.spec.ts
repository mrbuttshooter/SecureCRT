import { test, expect, type Page } from '@playwright/test'
import { closeWindow, openMenu, openPage, signIn as signInWith, signedIn } from './ui'

// These run against a real bkd binary with a real database, driving the
// browser the way a person would. They exist to catch what unit tests
// structurally cannot: whether the embedded frontend, the strict content
// security policy, the cookie flags and the API actually work together.

const BASE = process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500'
const EMAIL = 'admin@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

test.beforeEach(async ({ page }) => {
  // A content security policy violation surfaces only as a console message,
  // so watching for it is what makes the policy meaningful rather than
  // decorative. The browser also logs a console error for every non-2xx
  // fetch, and the app legitimately makes one — the initial whoami check
  // returns 401 when signed out — so that noise is filtered rather than the
  // whole guard being dropped.
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

/**
 * signIn signs in and opens the vault, creating it on first use.
 *
 * Written to handle either state so that every test can run on its own —
 * `--grep` a single test and it still works. An earlier version relied on the
 * tests running in order, which meant one failure cascaded into the next and
 * made the real cause hard to find.
 */
async function signIn(page: Page) {
  await signInWith(page, { email: EMAIL, password: PASSWORD, passphrase: PASSPHRASE })
}

/** openCredentials opens the Credentials window from the Tools menu. */
async function openCredentials(page: Page) {
  const win = await openPage(page, 'credentials')
  // Exact: the window's own title also begins with "Credentials".
  await expect(win.getByRole('heading', { name: 'Credentials', exact: true })).toBeVisible()
  return win
}

/** generateKey creates a key through the interface and returns its window. */
async function generateKey(page: Page, name: string) {
  const win = await openCredentials(page)
  await win.getByRole('button', { name: 'Generate SSH key' }).click()
  await win.getByLabel('Name', { exact: true }).fill(name)
  await win.getByRole('button', { name: 'Generate', exact: true }).click()
  await expect(win.getByRole('heading', { name: 'Key created' })).toBeVisible()
  return win
}

test('signs in, sets up a vault, and generates a key', async ({ page }) => {
  await page.goto(BASE)

  await expect(page.getByRole('heading', { name: 'Bridgekeeper' })).toBeVisible()

  await page.getByLabel('Email address', { exact: true }).fill(EMAIL)
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()

  // A fresh account is asked to create a vault before anything else.
  await expect(page.getByRole('heading', { name: 'Set up your vault' })).toBeVisible()

  await page.getByLabel('Choose a passphrase', { exact: true }).fill(PASSPHRASE)
  await page.getByLabel('Repeat it', { exact: true }).fill(PASSPHRASE)
  await page.getByRole('button', { name: 'Create vault' }).click()

  // The terminal workspace is the landing screen.
  await signedIn(page)
  await expect(page.getByRole('heading', { name: 'No session open' })).toBeVisible()

  const win = await openCredentials(page)
  await expect(win.getByText('No credentials yet.')).toBeVisible()

  // Generate a key.
  await win.getByRole('button', { name: 'Generate SSH key' }).click()
  await win.getByLabel('Name', { exact: true }).fill('Production jump host')
  await win.getByRole('button', { name: 'Generate', exact: true }).click()

  await expect(win.getByRole('heading', { name: 'Key created' })).toBeVisible()

  // The public key and fingerprint are what the user needs...
  const body = await page.locator('body').innerText()
  expect(body).toContain('ssh-ed25519 ')
  expect(body).toContain('SHA256:')

  // ...and the private half must never appear anywhere on the page.
  expect(body).not.toContain('BEGIN OPENSSH PRIVATE KEY')
  expect(body).not.toContain('PRIVATE KEY')

  await win.getByRole('button', { name: 'Done' }).click()
  await expect(win.getByText('Production jump host', { exact: true })).toBeVisible()
})

test('a credential survives locking and reopening the vault', async ({ page }) => {
  await signIn(page)
  const win = await generateKey(page, 'Lock test key')
  await win.getByRole('button', { name: 'Done' }).click()
  await expect(win.getByText('Lock test key', { exact: true })).toBeVisible()

  // The main window, and with it the menu bar, is inert while a window is
  // open over it: close this one before reaching for File > Lock vault.
  await closeWindow(win)
  await openMenu(page, 'File', 'Lock vault')
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible()

  // A wrong passphrase is refused with a message, not a crash.
  await page.getByLabel('Passphrase', { exact: true }).fill('not the right passphrase')
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByText('That passphrase did not open your vault.')).toBeVisible()

  await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await signedIn(page)
  const reopened = await openCredentials(page)

  // Still there, which proves it decrypted under a key derived freshly from
  // the passphrase rather than one left in memory.
  await expect(reopened.getByText('Lock test key', { exact: true })).toBeVisible()
})

test('the session cookie is HttpOnly and SameSite=Strict', async ({ page, context }) => {
  await signIn(page)

  const cookies = await context.cookies()

  const session = cookies.find((c) => c.name === 'bkd_session')
  expect(session, 'the session cookie should be set').toBeTruthy()
  expect(session!.httpOnly, 'the session cookie must be HttpOnly').toBe(true)
  expect(session!.sameSite).toBe('Strict')

  // The CSRF cookie must be readable by script — that echo is the half of
  // the double-submit check a cross-origin page cannot perform.
  const csrf = cookies.find((c) => c.name === 'bkd_csrf')
  expect(csrf, 'the CSRF cookie should be set').toBeTruthy()
  expect(csrf!.httpOnly, 'the CSRF cookie must be readable by script').toBe(false)
})

test('signing out ends the session', async ({ page }) => {
  await signIn(page)

  await openMenu(page, 'File', 'Sign out')
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()

  // And a reload must not resurrect it.
  await page.reload()
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
})

test('sets up two-factor authentication', async ({ page }) => {
  await signIn(page)

  const win = await openPage(page, 'security')
  await expect(win.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible()

  await win.getByRole('button', { name: 'Set up' }).click()
  await expect(win.getByRole('heading', { name: 'Set up your authenticator' })).toBeVisible()

  // The QR code renders from a data URI, which the content security policy
  // has to permit — if img-src lacked data:, this would be blocked.
  const qr = page.getByAltText('QR code for authenticator setup')
  await expect(qr).toBeVisible()
  expect(await qr.getAttribute('src')).toMatch(/^data:image\/png;base64,/)
})
