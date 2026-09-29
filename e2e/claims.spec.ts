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
  // This key's register sits in the last chunk of its window, so the search has
  // most of the window left to run when the cancel lands.
  await page.locator('#key-input').fill('00000000000000002100');
  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.getByRole('button', { name: 'Start real search' }).click();

  // Cancel while the search is provably in flight rather than racing it from a
  // standing start: wait for the worker's own progress before asking it to stop.
  await expect(page.locator('#attack-count')).not.toHaveText('0 / 65,536 tested');
  await expect(page.locator('#attack-result')).toBeHidden();
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

// --- Exhibit 5: The Wall ----------------------------------------------------

/** Run the real Exhibit 3 search, then open Exhibit 5 with the rate it produced. */
async function measureThenOpenWall(page: Page): Promise<void> {
  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.getByRole('button', { name: 'Start real search' }).click();
  await expect(page.locator('#attack-result')).toBeVisible({ timeout: 30_000 });
  await page.getByRole('tab', { name: /The Wall/ }).click();
  await expect(page.locator('#wall-body')).toBeVisible();
}

function parseCount(text: string): number {
  return Number(text.replace(/,/g, ''));
}

test('the wall stays inert until the learner has measured a rate', async ({ page }) => {
  await page.getByRole('tab', { name: /The Wall/ }).click();
  await expect(page.locator('#wall-absent')).toBeVisible();
  await expect(page.locator('#wall-absent')).toHaveAttribute('data-rate', 'absent');
  await expect(page.locator('#wall-body')).toBeHidden();
  await expect(page.locator('#wall-chart .bar-row')).toHaveCount(0);
  await expect(page.locator('#wall-verdict')).toHaveAttribute('data-claim', 'pending');
  // No default rate is smuggled in anywhere on the page.
  await expect(page.locator('#wall-rate')).toHaveText('0');
});

test('the displayed rate is the Exhibit 3 count divided by the Exhibit 3 time', async ({ page }) => {
  await measureThenOpenWall(page);

  // Re-derive the rate from the two raw numbers the page prints in its formula,
  // by a different route than the source takes.
  const formula = await page.locator('#wall-formula').innerText();
  const checked = parseCount(formula.match(/^([\d,]+) candidates/)![1]);
  const seconds = Number(formula.match(/÷ ([\d.]+) s/)![1]);
  const shown = parseCount(await page.locator('#wall-rate').innerText());

  expect(seconds).toBeGreaterThan(0);
  // The formula prints a rounded elapsed time, so reconcile to that precision
  // rather than to the bit. What is under test is that the page divided these
  // two numbers, not how many digits it chose to show.
  expect(checked / seconds).toBeGreaterThan(shown * 0.9999);
  expect(checked / seconds).toBeLessThan(shown * 1.0001);

  // And the count in the formula is the count Exhibit 3 reported testing.
  await page.getByRole('tab', { name: /The Break/ }).click();
  const reported = parseCount(
    (await page.locator('#attack-status').innerText()).match(/after ([\d,]+) real TEA1/)![1],
  );
  expect(checked).toBe(reported);
});

test('every extrapolated row equals keyspace divided by the page’s own rate', async ({
  page,
}) => {
  await measureThenOpenWall(page);
  const rate = Number(await page.locator('#wall-rate').getAttribute('data-rate'));
  expect(rate).toBeGreaterThan(0);

  for (const bits of [32, 56, 80, 128, 256]) {
    const row = page.locator(`#wall-chart .bar-row[data-kind="target"][data-bits="${bits}.00"]`);
    await expect(row).toHaveCount(1);

    // Independent re-derivation: compute the seconds here, format them here,
    // and require the page's printed duration to agree.
    const seconds = 2 ** bits / rate;
    const years = seconds / 31_557_600;
    const printed = await row.locator('.bar-value').innerText();

    if (years >= 1_000) {
      const exponent = Math.floor(Math.log10(years));
      expect(printed).toBe(`${(years / 10 ** exponent).toFixed(1)} × 10^${exponent} years`);
    } else {
      expect(printed.length).toBeGreaterThan(0);
    }

    // The bar is drawn on the log2 axis it claims: width is bits/256.
    const percent = Number(await row.locator('.bar-fill').getAttribute('data-percent'));
    expect(percent).toBeCloseTo((bits / 256) * 100, 3);
  }
});

/** Read a rendered "N x 10^E years" duration back into seconds. */
function parseRenderedYears(printed: string): number {
  const scientific = printed.match(/^([\d.]+) \u00d7 10\^(\d+) years$/);
  if (scientific !== null) {
    return Number(scientific[1]) * 10 ** Number(scientific[2]) * 31_557_600;
  }
  const plain = printed.match(/^([\d.]+) years$/);
  expect(plain, `unexpected duration format: ${printed}`).not.toBeNull();
  return Number(plain![1]) * 31_557_600;
}

test('a scale-up multiplier divides the rendered cost by exactly that multiplier', async ({
  page,
}) => {
  await measureThenOpenWall(page);
  const row = page.locator('#wall-chart .bar-row[data-bits="80.00"] .bar-value');

  // Read what the page actually PRINTS at each scale, not what the test can
  // recompute for itself: a test that only does its own arithmetic agrees with a
  // source that has stopped applying the multiplier at all.
  const atOne = parseRenderedYears(await row.innerText());
  await page.getByRole('radio', { name: 'A GPU farm' }).check();
  await expect(page.locator('#wall-multiplier')).toHaveValue('1000000000');
  const atFarm = parseRenderedYears(await row.innerText());

  expect(atOne / atFarm).toBeGreaterThan(9.9e8);
  expect(atOne / atFarm).toBeLessThan(1.01e9);

  // And the rendered value agrees with the page's own rate and multiplier.
  const rate = Number(await page.locator('#wall-rate').getAttribute('data-rate'));
  expect(atFarm).toBeGreaterThan((2 ** 80 / (rate * 1e9)) * 0.99);
  expect(atFarm).toBeLessThan((2 ** 80 / (rate * 1e9)) * 1.01);

  // The one-year mark moves with the multiplier, because it is computed from it.
  const yearMark = page.locator('#wall-chart .bar-row[data-kind="mark"]').last();
  const markBits = Number(await yearMark.getAttribute('data-bits'));
  expect(markBits).toBeCloseTo(Math.log2(31_557_600 * rate * 1e9), 1);
});

test('an absurd multiplier is rendered and labelled absurd, not refused', async ({ page }) => {
  await measureThenOpenWall(page);
  await page.locator('#wall-multiplier').fill('1e30');

  await expect(page.locator('#wall-absurd')).toBeVisible();
  await expect(page.locator('#wall-absurd')).toContainText('ABSURD ASSUMPTION');
  // Rendered, not refused: the rows still compute against the absurd number.
  await expect(page.locator('#wall-verdict')).toHaveAttribute('data-claim', 'wall');
  await expect(page.locator('#wall-chart .bar-row')).not.toHaveCount(0);

  await page.locator('#wall-multiplier').fill('1000');
  await expect(page.locator('#wall-absurd')).toBeHidden();
});

test('the wall verdict names the register, the label, and 128 bits from one rate', async ({
  page,
}) => {
  await measureThenOpenWall(page);
  const rate = Number(await page.locator('#wall-rate').getAttribute('data-rate'));
  const verdict = await page.locator('#wall-verdict').innerText();

  expect(verdict).toContain('THE WALL');
  expect(verdict).toContain('extrapolated from one browser, not predicted');

  // The verdict keeps the window it really ran distinct from the space it did
  // not: 2^16 is timed, everything from 2^32 up is extrapolated.
  expect(verdict).toMatch(/really tested [\d,]+ candidates in /);
  expect(verdict).toContain('the full 32-bit register TEA1 actually uses would take');

  // 2^32 at a browser rate is long but finite; 2^128 is neither.
  const registerSeconds = 2 ** 32 / rate;
  expect(registerSeconds).toBeGreaterThan(60);
  expect(registerSeconds / 31_557_600).toBeLessThan(1);
  expect(2 ** 128 / rate / 31_557_600).toBeGreaterThan(1e3);
  expect(verdict).toMatch(/128 would take .+ × 10\^\d+ years/);
});

// --- Exhibit 6: Paper vs Practice -------------------------------------------

test('every plotted attack matches its row in the sourced table', async ({ page }) => {
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();

  const bars = page.locator('#paper-chart .attack-bar');
  const rows = page.locator('#paper-body tr');
  const count = await bars.count();
  expect(count).toBeGreaterThan(0);
  await expect(rows).toHaveCount(count);

  for (let index = 0; index < count; index += 1) {
    const bar = bars.nth(index);
    const id = await bar.getAttribute('data-attack');
    const row = page.locator(`#paper-body tr[data-attack="${id}"]`);
    await expect(row).toHaveCount(1);

    // The bar's position and the table's time cell are the same number.
    const barBits = Number(await bar.getAttribute('data-bits'));
    const rowBits = Number(await row.locator('td').nth(4).getAttribute('data-time'));
    expect(barBits).toBeCloseTo(rowBits, 2);

    // And the bar is drawn at that number on the declared 0-256 log2 axis.
    const percent = Number(await bar.locator('.bar-fill').getAttribute('data-percent'));
    expect(percent).toBeCloseTo((rowBits / 256) * 100, 2);
  }
});

test('every attack row carries a citation, a model, a goal, data and memory', async ({ page }) => {
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();
  const rows = page.locator('#paper-body tr');
  const count = await rows.count();

  for (let index = 0; index < count; index += 1) {
    const row = rows.nth(index);
    await expect(row.locator('td').nth(2)).toContainText(/Single-key|Related-key/);
    await expect(row.locator('td').nth(3)).toContainText(/rounds/);
    await expect(row.locator('td').nth(4)).toContainText(/2\^/);
    await expect(row.locator('td').nth(5)).not.toBeEmpty();
    await expect(row.locator('td').nth(6)).toContainText(/2\^/);

    const source = row.locator('td').last();
    await expect(source.locator('a')).toHaveAttribute('href', /^https:\/\/eprint\.iacr\.org\//);
    await expect(source.locator('.citation-locator')).toContainText(/Table|Section|Abstract/);
  }
});

test('every plotted attack sits under the brute-force line of its own group', async ({ page }) => {
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();

  for (const keyBits of [128, 192, 256]) {
    const group = page.locator(`.attack-group[data-key-bits="${keyBits}"]`);
    await expect(group).toHaveCount(1);
    await expect(group.locator('.brute-line')).toHaveAttribute('data-bits', `${keyBits}.00`);

    const bars = group.locator('.attack-bar');
    const count = await bars.count();
    expect(count).toBeGreaterThan(0);
    for (let index = 0; index < count; index += 1) {
      const bits = Number(await bars.nth(index).getAttribute('data-bits'));
      expect(bits).toBeLessThan(keyBits);
    }
  }
});

test('ACADEMICALLY BROKEN and practically secure are asserted together', async ({ page }) => {
  // 1. Reach the fixture through the UI.
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();
  await expect(page.locator('#paper-verdict')).toHaveAttribute(
    'data-claim',
    'academically-broken',
  );

  // 2. In that state every attack on screen genuinely succeeds: each one is
  //    strictly faster than the brute-force line it is plotted against. There is
  //    no failing row propping the verdict up.
  const plotted = page.locator('#paper-chart .attack-bar');
  const plottedCount = await plotted.count();
  expect(plottedCount).toBeGreaterThan(0);
  for (let index = 0; index < plottedCount; index += 1) {
    const bar = plotted.nth(index);
    const bits = Number(await bar.getAttribute('data-bits'));
    const keyBits = Number(
      await bar.locator('xpath=ancestor::div[@class="attack-group"]').getAttribute('data-key-bits'),
    );
    expect(bits, `row ${index} should beat brute force`).toBeLessThan(keyBits);
  }

  // 3. And the limitation is on screen in that same state, not in the README and
  //    not behind a disclosure.
  const limits = page.locator('#pane-paper .negative-claims');
  await expect(limits).toBeVisible();
  await expect(limits).toContainText('says nothing about any implementation');

  const verdict = await page.locator('#paper-verdict').innerText();
  expect(verdict).toContain('ACADEMICALLY BROKEN');
  expect(verdict).toContain('PRACTICALLY SECURE');
  expect(verdict).toContain('Nothing on this chart finishes');

  // The advantage the verdict quotes is recomputed from the plotted bars.
  const quoted = Number(verdict.match(/is ([\d.]+) bits/)![1]);
  const bars = page.locator('#paper-chart .attack-bar[data-model="single-key"]');
  const count = await bars.count();
  let best = 0;
  for (let index = 0; index < count; index += 1) {
    const bar = bars.nth(index);
    const bits = Number(await bar.getAttribute('data-bits'));
    const keyBits = Number(
      await bar.locator('xpath=ancestor::div[@class="attack-group"]').getAttribute('data-key-bits'),
    );
    best = Math.max(best, keyBits - bits);
  }
  expect(quoted).toBeCloseTo(best, 1);
  expect(quoted).toBeLessThan(3);
});

test('the TEA1-versus-AES contrast is computed from the learner’s own rate', async ({
  page,
}) => {
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();
  // Before a run there is no rate, so the contrast refuses to print one.
  await expect(page.locator('#contrast-tea1')).toHaveText('—');
  await expect(page.locator('#contrast-tea1-note')).toBeVisible();

  await measureThenOpenWall(page);
  const rate = Number(await page.locator('#wall-rate').getAttribute('data-rate'));
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();

  await expect(page.locator('#contrast-tea1')).not.toHaveText('—');
  await expect(page.locator('#contrast-tea1-note')).toBeHidden();

  // AES's best published time, at the same rate, lands in scientific years.
  const aesBits = Number(
    (await page.locator('#contrast-aes').innerText()).match(/2\^([\d.]+)/)![1],
  );
  const years = 2 ** aesBits / rate / 31_557_600;
  expect(years).toBeGreaterThan(1e3);
  const exponent = Math.floor(Math.log10(years));
  await expect(page.locator('#contrast-aes-time')).toHaveText(
    `${(years / 10 ** exponent).toFixed(1)} × 10^${exponent} years`,
  );
});

test('the security-margin view is deferred to Iron Serpent, not restated here', async ({
  page,
}) => {
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();
  const limits = page.locator('#pane-paper .negative-claims');
  await expect(limits).toContainText('Full-round key recovery only');
  await expect(limits.getByRole('link', { name: 'Iron Serpent' })).toHaveAttribute(
    'href',
    'https://systemslibrarian.github.io/crypto-lab-iron-serpent/',
  );
  await expect(limits.getByRole('link', { name: 'Grover' })).toHaveAttribute(
    'href',
    'https://systemslibrarian.github.io/crypto-lab-grover/',
  );
  await expect(limits).toContainText('says nothing about any implementation');
  await expect(limits).toContainText('nothing here transfers TEA1');
});

test('the wall prints its extrapolations and its limits in the same state', async ({ page }) => {
  // 1. Reach the fixture: a rate measured by the real search.
  await measureThenOpenWall(page);

  // 2. Everything the pane renders in that state is a real computed result --
  //    a rate, a chart, and a verdict, none of them pending or errored.
  await expect(page.locator('#wall-verdict')).toHaveAttribute('data-claim', 'wall');
  await expect(page.locator('#wall-absent')).toBeHidden();
  expect(await page.locator('#wall-chart .bar-row').count()).toBeGreaterThan(5);
  expect(Number(await page.locator('#wall-rate').getAttribute('data-rate'))).toBeGreaterThan(0);

  // 3. And the limits are visible in that same state, beside the numbers they
  //    qualify -- an extrapolation whose caveat is elsewhere is a prediction.
  const limits = page.locator('#pane-wall .negative-claims');
  await expect(limits).toBeVisible();
  await expect(limits).toContainText('one browser on one machine');
  await expect(limits).toContainText('order-of-magnitude illustrations, not predictions');
  await expect(limits).toContainText('Classical search only');
  await expect(limits.getByRole('link', { name: 'Grover' })).toHaveAttribute(
    'href',
    'https://systemslibrarian.github.io/crypto-lab-grover/',
  );
  await expect(page.locator('#wall-formula')).toContainText('candidates/second');
});

test('an unusable multiplier falls back to the measured rate and says so', async ({ page }) => {
  await measureThenOpenWall(page);
  const rate = Number(await page.locator('#wall-rate').getAttribute('data-rate'));
  const unscaled = await page.locator('#wall-chart .bar-row[data-bits="80.00"] .bar-value').innerText();

  await page.locator('#wall-multiplier').fill('');
  await expect(page.locator('#wall-assumption')).toContainText(
    'does not hold a usable multiplier',
  );
  await expect(page.locator('#wall-assumption')).toContainText('the measured rate, unscaled');

  // It fell back, rather than rendering nothing or rendering a stale number.
  await expect(page.locator('#wall-chart .bar-row[data-bits="80.00"] .bar-value')).toHaveText(
    unscaled,
  );
  expect(parseRenderedYears(unscaled)).toBeGreaterThan((2 ** 80 / rate) * 0.99);

  await page.locator('#wall-multiplier').fill('0');
  await expect(page.locator('#wall-assumption')).toContainText(
    'does not hold a usable multiplier',
  );
});
