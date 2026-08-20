import { test, expect } from '@playwright/test'

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

  await expect(page.getByRole('heading', { name: 'Credentials' })).toBeVisible()
}

/** generateKey creates a key through the interface and returns its name. */
async function generateKey(page: import('@playwright/test').Page, name: string) {
  await page.getByRole('button', { name: 'Generate SSH key' }).click()
  await page.getByLabel('Name', { exact: true }).fill(name)
  await page.getByRole('button', { name: 'Generate', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Key created' })).toBeVisible()
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

  await expect(page.getByRole('heading', { name: 'Credentials' })).toBeVisible()
  await expect(page.getByText('No credentials yet.')).toBeVisible()

  // Generate a key.
  await page.getByRole('button', { name: 'Generate SSH key' }).click()
  await page.getByLabel('Name', { exact: true }).fill('Production jump host')
  await page.getByRole('button', { name: 'Generate', exact: true }).click()

  await expect(page.getByRole('heading', { name: 'Key created' })).toBeVisible()

  // The public key and fingerprint are what the user needs...
  const body = await page.locator('body').innerText()
  expect(body).toContain('ssh-ed25519 ')
  expect(body).toContain('SHA256:')

  // ...and the private half must never appear anywhere on the page.
  expect(body).not.toContain('BEGIN OPENSSH PRIVATE KEY')
  expect(body).not.toContain('PRIVATE KEY')

  await page.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByText('Production jump host', { exact: true })).toBeVisible()
})

test('a credential survives locking and reopening the vault', async ({ page }) => {
  await signIn(page)
  await generateKey(page, 'Lock test key')
  await page.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByText('Lock test key', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'Lock vault' }).click()
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible()

  // A wrong passphrase is refused with a message, not a crash.
  await page.getByLabel('Passphrase', { exact: true }).fill('not the right passphrase')
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByText('That passphrase did not open your vault.')).toBeVisible()

  await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('heading', { name: 'Credentials' })).toBeVisible()

  // Still there, which proves it decrypted under a key derived freshly from
  // the passphrase rather than one left in memory.
  await expect(page.getByText('Lock test key', { exact: true })).toBeVisible()
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

  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()

  // And a reload must not resurrect it.
  await page.reload()
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
})

test('sets up two-factor authentication', async ({ page }) => {
  await signIn(page)

  await page.getByRole('button', { name: 'Security' }).click()
  await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible()

  await page.getByRole('button', { name: 'Set up' }).click()
  await expect(page.getByRole('heading', { name: 'Set up your authenticator' })).toBeVisible()

  // The QR code renders from a data URI, which the content security policy
  // has to permit — if img-src lacked data:, this would be blocked.
  const qr = page.getByAltText('QR code for authenticator setup')
  await expect(qr).toBeVisible()
  expect(await qr.getAttribute('src')).toMatch(/^data:image\/png;base64,/)
})
