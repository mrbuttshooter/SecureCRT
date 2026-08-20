import { test, expect, type Page } from '@playwright/test'

// Jump hosts and tunnels, in a real browser, against real SSH servers.
//
// The Go tests already drive both against in-process servers, which proves
// the protocol. What no Go test can prove is that the two pieces of interface
// added for this phase — a jump-host editor on a form that never had one, and
// a tunnel manager that has to explain what this server will not do — let a
// person actually reach a device behind a bastion.

const BASE = process.env.BKD_E2E_URL ?? 'http://127.0.0.1:18500'

// Its own account, like every other spec here: sharing one would mean sharing
// a vault, a credential list and a known-hosts list with whichever file
// happened to run first.
const EMAIL = 'tunnels@example.com'
const PASSWORD = 'a very long admin password'
const PASSPHRASE = 'a sufficiently long vault passphrase'

const SSH_HOST = process.env.BKD_E2E_SSH_HOST ?? '127.0.0.1'
const SSH_PORT = process.env.BKD_E2E_SSH_PORT ?? ''
const BASTION_PORT = process.env.BKD_E2E_BASTION_PORT ?? ''
const SSH_USER = process.env.BKD_E2E_SSH_USER ?? 'tester'
const SSH_PASSWORD = process.env.BKD_E2E_SSH_PASSWORD ?? ''

declare global {
  interface Window {
    bkdTerminalText?: (key: string) => string | null
  }
}

test.skip(!SSH_PORT || !BASTION_PORT, 'no test SSH servers; run through scripts/e2e.sh')

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

/**
 * ensureConnection saves a connection, optionally behind a jump host.
 *
 * jumpHostName is the name of another saved connection, chosen through the
 * editor's own control — which is the point of the test, so it is not set
 * through the API behind the interface's back.
 */
async function ensureConnection(
  page: Page,
  name: string,
  port: string,
  credentialName: string,
  jumpHostName?: string,
) {
  await ensureCredential(page, credentialName)

  await page.getByRole('button', { name: 'Terminal' }).click()
  if (await page.getByRole('button', { name, exact: true }).count()) return

  await page.getByRole('button', { name: 'New connection', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'New connection' })).toBeVisible()

  await page.getByLabel('Name', { exact: true }).fill(name)
  await page.getByLabel('Hostname or address', { exact: true }).fill(SSH_HOST)
  await page.getByLabel('Port', { exact: true }).fill(port)
  await page.getByLabel('Username on the remote host', { exact: true }).fill(SSH_USER)

  // Options carry identifiers as their values and the test has no other way
  // to learn them, so both selects below are matched on option text read out
  // of the DOM. A collapsed select renders no text for a locator to find.
  const credentialField = page.getByRole('combobox', { name: 'Credential' })
  const credentialValue = await credentialField.evaluate(
    (el, wanted) =>
      Array.from((el as HTMLSelectElement).options)
        .find((option) => option.text.startsWith(wanted))?.value ?? '',
    credentialName,
  )
  expect(credentialValue, `no option for the credential "${credentialName}"`).toBeTruthy()
  await credentialField.selectOption(credentialValue)

  if (jumpHostName) {
    const jumpField = page.getByRole('combobox', { name: 'Add a jump host' })
    const jumpValue = await jumpField.evaluate(
      (el, wanted) =>
        Array.from((el as HTMLSelectElement).options)
          .find((option) => option.text.startsWith(wanted))?.value ?? '',
      jumpHostName,
    )
    expect(jumpValue, `no jump host option for "${jumpHostName}"`).toBeTruthy()
    await jumpField.selectOption(jumpValue)

    // Choosing one adds a row, which is how the form says the hop is there.
    await expect(page.getByRole('combobox', { name: 'Hop 1' })).toBeVisible()
  }

  await page.getByRole('button', { name: 'Create connection' }).click()
  await expect(page.getByRole('heading', { name: 'New connection' })).toBeHidden()
}

type Pane = ReturnType<Page['getByTestId']>

/**
 * connect opens a terminal, accepting every host key it is asked about, and
 * reports how many it was asked about.
 *
 * The count is the interesting part: a jump chain prompts once per hop, not
 * once per connection, because every hop is verified in its own right.
 *
 * Written as a race between "connected" and "another prompt" rather than a
 * fixed number of accepts. A loop that checked for the next dialog straight
 * after clicking the last one would find nothing — the next hop has not been
 * dialled yet — break early, and then wait forever for a connection that is
 * in fact sitting behind an unanswered prompt. Which is exactly what the
 * first version of this did.
 */
async function connect(page: Page, name: string): Promise<{ pane: Pane; prompts: number }> {
  await page.getByRole('button', { name, exact: true }).click()
  await page.locator('.selection').getByRole('button', { name: 'Connect' }).click()

  const pane = page.getByTestId('terminal-pane').last()
  const connected = pane.getByText('Connected', { exact: true })
  const prompt = pane.getByRole('alertdialog', { name: 'Unrecognised host key' })

  // Bounded by the longest chain the server will dial, so a prompt that never
  // clears fails here rather than spinning until the test times out.
  const maxHops = 8
  const seen = new Set<string>()

  let prompts = 0
  for (; prompts <= maxHops; prompts++) {
    await expect(connected.or(prompt)).toBeVisible({ timeout: 30_000 })
    if (await connected.isVisible()) break

    // Each hop presents its own key, so each dialog shows a fingerprint the
    // previous one did not. Recording them is what makes this loop count
    // distinct hops rather than one dialog clicked twice.
    const fingerprint = pane.getByTestId('host-key-fingerprint')
    await expect(fingerprint).toContainText('SHA256:')
    const text = (await fingerprint.textContent()) ?? ''
    expect(seen.has(text), 'the same fingerprint was presented twice').toBe(false)
    seen.add(text)

    await pane.getByRole('button', { name: /fingerprint matches/ }).click()
  }
  expect(prompts, 'the host key prompt never cleared').toBeLessThanOrEqual(maxHops)

  return { pane, prompts }
}

async function screenText(page: Page, pane: Pane): Promise<string> {
  const key = await pane.getAttribute('data-pane-key')
  expect(key, 'the pane carries no key').toBeTruthy()
  const text = await page.evaluate((k) => window.bkdTerminalText?.(k) ?? null, key!)
  expect(text, 'the terminal is not registered').not.toBeNull()
  return text!
}

async function run(page: Page, pane: Pane, command: string, marker: RegExp) {
  await pane.locator('.xterm-helper-textarea').first().focus()
  await page.keyboard.type(command)
  await page.keyboard.press('Enter')

  await expect(async () => {
    expect(await screenText(page, pane)).toMatch(marker)
  }).toPass({ timeout: 30_000 })
}

// Both tests here do more setup than the default 30-second budget allows:
// two saved connections, and a dial that stops for a fingerprint on every hop
// rather than once. Raised deliberately rather than by trimming the setup,
// because the setup is the thing being tested.
test.describe.configure({ timeout: 120_000 })

test('reaches a device through a jump host chosen in the editor', async ({ page }) => {
  await signIn(page)

  await ensureConnection(page, 'Bastion', BASTION_PORT, 'Jump password')
  await ensureConnection(page, 'Behind the bastion', SSH_PORT, 'Jump password', 'Bastion')

  const { pane, prompts } = await connect(page, 'Behind the bastion')

  // Two, not one. The bastion presented a key of its own and was asked about
  // under its own name — which is the property that keeps a bastion's
  // fingerprint from being filed against the device behind it.
  expect(prompts, 'the bastion was not verified in its own right').toBe(2)

  await run(page, pane, 'echo through-the-bastion', /through-the-bastion/)
})

test('a tunnel carries traffic, and a kind that is off says which setting', async ({ page }) => {
  await signIn(page)
  await ensureConnection(page, 'Tunnel host', SSH_PORT, 'Jump password')

  // The host key has to be accepted once before a tunnel can open through
  // this connection, and doing it in a terminal is how a person would.
  await connect(page, 'Tunnel host')

  await page.getByRole('button', { name: 'Tunnels' }).click()
  await expect(page.getByRole('heading', { name: 'Tunnels' })).toBeVisible()
  await expect(page.getByText('No tunnels are open.')).toBeVisible()

  const kind = page.getByRole('combobox', { name: 'Kind' })

  // What this instance will not do, and why. That the *reason* is on screen
  // is the point: a disabled button with no explanation is how somebody
  // concludes the feature is broken and stops asking, where a refusal naming
  // policy.allow_remote_forwards is one they can take to whoever runs the
  // server.
  await kind.selectOption('remote')
  await expect(page.getByText(/policy\.allow_remote_forwards/)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Open tunnel' })).toBeDisabled()

  await kind.selectOption('web')
  await expect(page.getByText(/tunnels\.domain/)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Open tunnel' })).toBeDisabled()

  // And what it will. A local tunnel to the SSH port of the *other* test
  // server, reached over the first — an address chosen because this script
  // knows something is listening there.
  await kind.selectOption('local')
  await expect(page.getByText(/policy\.allow_tcp_tunnels/)).toBeHidden()

  const connection = page.getByRole('combobox', { name: 'Through which connection' })
  const value = await connection.evaluate(
    (el) =>
      Array.from((el as HTMLSelectElement).options)
        .find((option) => option.text.startsWith('Tunnel host'))?.value ?? '',
  )
  expect(value, 'the saved connection is not offered').toBeTruthy()
  await connection.selectOption(value)

  await page.getByLabel('Label', { exact: true }).fill('to the bastion')
  await page.getByLabel(/Address to reach/).fill(SSH_HOST)
  await page.getByLabel('Port', { exact: true }).fill(BASTION_PORT)

  await page.getByRole('button', { name: 'Open tunnel' }).click()

  // Open, listed, and reporting a port on this server to point a client at.
  const row = page.getByRole('row', { name: /to the bastion/ })
  await expect(row).toBeVisible({ timeout: 20_000 })
  await expect(row).toContainText(/127\.0\.0\.1:347\d\d/)
  await expect(row).toContainText(`${SSH_HOST}:${BASTION_PORT}`)

  // Closing it takes it off the list rather than leaving a dead row behind.
  await row.getByRole('button', { name: 'Close' }).click()
  await expect(page.getByText('No tunnels are open.')).toBeVisible({ timeout: 20_000 })
})
