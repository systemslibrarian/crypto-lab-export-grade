import { expect, test, type Page } from '@playwright/test';

function parseHex(text: string): number[] {
  const compact = text.replace(/\s+/g, '');
  return compact.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? [];
}

async function openReductionAndComplete(page: Page): Promise<void> {
  await page.getByRole('tab', { name: /The Reduction/ }).click();
  await page.getByRole('button', { name: 'Run all ten' }).click();
  await expect(page.locator('#trace-body tr')).toHaveCount(10);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
});

test('page keystream equals the external TEA1 known-answer fixture', async ({ page }) => {
  expect(parseHex(await page.locator('#keystream-output').innerText())).toEqual([
    0xd3, 0x3f, 0xd8, 0xa6, 0x05, 0xa0, 0xa1, 0xbb, 0x90, 0x23,
  ]);
  await expect(page.locator('#kat-verdict')).toHaveAttribute('data-kat', 'pass');
});

test('the displayed 80-to-32 claim is computed from rendered byte widths', async ({ page }) => {
  await openReductionAndComplete(page);

  const inputGroups = await page.locator('#key-bit-grid .bit-group').count();
  const inputBits = await page.locator('#key-bit-grid .bit').count();
  const registerGroups = await page.locator('#register-bit-grid .bit-group').count();
  const registerBits = await page.locator('#register-bit-grid .bit').count();

  expect(inputGroups).toBe(10);
  expect(registerGroups).toBe(4);
  expect(inputBits).toBe(inputGroups * 8);
  expect(registerBits).toBe(registerGroups * 8);
  await expect(page.locator('#nominal-bits')).toHaveText(String(inputBits));
  await expect(page.locator('#effective-bits')).toHaveText(String(registerBits));
  await expect(page.locator('#register-output')).toHaveText('0xc24e273b');
});

test('known plaintext derives the shown keystream and the worker recovers the reduction output', async ({ page }) => {
  await openReductionAndComplete(page);
  const reducedRegister = await page.locator('#register-output').innerText();
  await page.getByRole('tab', { name: /The Break/ }).click();

  const plaintext = parseHex(await page.locator('#plaintext-input').inputValue());
  const ciphertext = parseHex(await page.locator('#ciphertext-output').innerText());
  const displayedKeystream = parseHex(await page.locator('#known-stream-output').innerText());
  expect(plaintext.map((byte, index) => byte ^ ciphertext[index])).toEqual(displayedKeystream);

  await page.getByRole('button', { name: 'Start real search' }).click();
  await expect(page.locator('#attack-result')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#recovered-register')).toHaveText(reducedRegister);
  await expect(page.locator('#verification-output')).toHaveText(
    `${displayedKeystream.length} / ${displayedKeystream.length} keystream bytes reproduced exactly`,
  );
  await expect(page.locator('#attack-result')).toHaveAttribute('data-check', 'pass');
});

test('KAT success and 32-bit limitation coexist as OK-AND-BROKEN', async ({ page }) => {
  await openReductionAndComplete(page);
  await expect(page.locator('#kat-verdict')).toHaveAttribute('data-kat', 'pass');
  await expect(page.locator('#reduction-verdict')).toHaveAttribute('data-claim', 'ok-and-broken');
  await expect(page.locator('#reduction-verdict')).toContainText(
    'KAT passes, while the generator receives 32 computed bits',
  );
});

test('invalid and too-short fixtures fail with the actual cause', async ({ page }) => {
  await page.locator('#key-input').fill('00');
  await page.getByRole('button', { name: 'Generate keystream' }).click();
  await expect(page.locator('#cipher-error')).toContainText('exactly 10 bytes');

  await page.locator('#key-input').fill('00000000000000000000');
  await page.getByRole('button', { name: 'Generate keystream' }).click();
  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.locator('#plaintext-input').fill('00000000');
  await page.getByRole('button', { name: 'Start real search' }).click();
  await expect(page.locator('#attack-error')).toContainText('nonzero known plaintext');
  await page.locator('#plaintext-input').fill('010203');
  await page.getByRole('button', { name: 'Start real search' }).click();
  await expect(page.locator('#attack-error')).toContainText('between 4 and 8 bytes');
});

test('hidden panels stay hidden until their real tabs are selected', async ({ page }) => {
  await expect(page.locator('#pane-reduction')).toHaveAttribute('hidden', '');
  await expect(page.locator('#pane-reduction')).toHaveCSS('display', 'none');
  await page.getByRole('tab', { name: /The Reduction/ }).click();
  await expect(page.locator('#pane-cipher')).toHaveAttribute('hidden', '');
  await expect(page.locator('#pane-cipher')).toHaveCSS('display', 'none');
  await expect(page.locator('#pane-reduction')).not.toHaveAttribute('hidden', '');
});

test('a no-op preserves a recovery while a changed input retires it', async ({ page }) => {
  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.getByRole('button', { name: 'Start real search' }).click();
  await expect(page.locator('#attack-result')).toBeVisible({ timeout: 30_000 });

  await page.locator('#plaintext-input').fill('524144494f');
  await expect(page.locator('#attack-result')).toBeVisible();
  await expect(page.locator('#retired-status')).toBeHidden();

  await page.locator('#plaintext-input').fill('524144494e');
  await expect(page.locator('#attack-result')).toBeHidden();
  await expect(page.locator('#retired-status')).toContainText('retired because an input changed');
});

test('worker cancellation produces no stale recovery verdict', async ({ page }) => {
  await page.locator('#key-input').fill('00000000000000002100');
  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.getByRole('button', { name: 'Start real search' }).click();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.locator('#attack-status')).toContainText('cancelled cleanly', {
    timeout: 30_000,
  });
  await expect(page.locator('#attack-result')).toBeHidden();
  await expect(page.getByRole('button', { name: 'Cancel' })).toBeDisabled();
});

test('tablist supports roving keyboard navigation', async ({ page }) => {
  const tabs = page.getByRole('tab');
  await tabs.first().focus();
  await page.keyboard.press('End');
  await expect(tabs.last()).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Home');
  await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('ArrowRight');
  await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
});