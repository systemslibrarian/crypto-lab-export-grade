import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
export const NARROW = { width: 380, height: 800 };

export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
  });
  return errors;
}

async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const state = window as unknown as {
        __quietFrames?: number;
        __settleStart?: number;
      };
      if (state.__settleStart === undefined) state.__settleStart = performance.now();

      const running = document.getAnimations().filter((animation) => {
        if (animation.playState !== 'running') return false;
        return animation.effect?.getComputedTiming().iterations !== Infinity;
      });
      state.__quietFrames = running.length === 0 ? (state.__quietFrames ?? 0) + 1 : 0;

      if (state.__quietFrames >= 6 || performance.now() - state.__settleStart > budget) {
        state.__quietFrames = 0;
        state.__settleStart = undefined;
        return true;
      }
      return false;
    },
    4_000,
    { polling: 'raf', timeout: 20_000 },
  );
}

async function expectOneBanner(page: Page): Promise<void> {
  await expect(page.getByRole('banner')).toHaveCount(1);
}

async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisibleText = await page.evaluate(() => {
    const failures: string[] = [];
    for (const element of Array.from(document.querySelectorAll<HTMLElement>('body *'))) {
      const ownText = Array.from(element.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent ?? '')
        .join('')
        .trim();
      if (!ownText || !element.checkVisibility({ checkVisibilityCSS: true })) continue;

      let opacity = 1;
      for (let current: Element | null = element; current; current = current.parentElement) {
        opacity *= Number.parseFloat(getComputedStyle(current).opacity);
      }
      if (opacity === 0) failures.push(element.id || element.className || element.tagName);
    }
    return Array.from(new Set(failures));
  });
  expect(invisibleText, `visible text at zero opacity in ${label}`).toEqual([]);
}

async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scrollWidth, `horizontal overflow in ${label}`).toBeLessThanOrEqual(
    dimensions.clientWidth,
  );
}

async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const focusable = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((element) => {
        const style = getComputedStyle(element);
        const scrolls =
          (['auto', 'scroll'].includes(style.overflowX) && element.scrollWidth > element.clientWidth + 1) ||
          (['auto', 'scroll'].includes(style.overflowY) && element.scrollHeight > element.clientHeight + 1);
        return scrolls && element.tabIndex < 0 && !element.querySelector(focusable);
      })
      .map((element) => element.id || element.className || element.tagName);
  });
  expect(unreachable, `scrolling regions without a keyboard route in ${label}`).toEqual([]);
}

async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const selector = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>(selector))
      .filter((element) => element.tabIndex >= 0)
      .filter((element) => element.checkVisibility({ checkVisibilityCSS: true }))
      .filter((element) => {
        const rect = element.getBoundingClientRect();
        let opacity = 1;
        for (let current: Element | null = element; current; current = current.parentElement) {
          opacity *= Number.parseFloat(getComputedStyle(current).opacity);
        }
        return opacity === 0 || rect.width === 0 || rect.height === 0;
      })
      .map((element) => element.id || element.className || element.tagName);
  });
  expect(invisible, `focus targets that paint nothing in ${label}`).toEqual([]);
}

async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const failures = await auditNonText(page);
  const newOrWorse = failures.filter((failure) => {
    const baseline = NONTEXT_BASELINE[`${failure.kind}|${failure.selector}`];
    return baseline === undefined || failure.ratio < baseline.ratio - 0.01;
  });
  expect(formatNonTextFailures(newOrWorse), `non-text contrast in ${label}`).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);

  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const violations = [...wcag.violations, ...landmarks.violations].map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
  expect(violations, `axe violations in ${label}`).toEqual([]);

  const incomplete = [...wcag.incomplete, ...landmarks.incomplete]
    .filter((result) => result.id !== 'color-contrast')
    .map((result) => ({
      id: result.id,
      targets: result.nodes.map((node) => node.target.join(' ')),
    }));
  expect(incomplete, `unexplained axe incomplete results in ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured text contrast in ${label}`).toEqual([]);
  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoInvisibleFocusTargets(page, label);
  await expectNoHorizontalOverflow(page, label);
}

export async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');

  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(
    true,
  );
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expectOneBanner(page);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('main#app')).toHaveCount(1);
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.getByRole('tab')).toHaveCount(5);
  await expect(page.getByRole('tab', { name: /The Cipher/ })).toHaveAttribute(
    'aria-selected',
    'true',
  );
  await expect(page.locator('#pane-cipher')).toBeVisible();
  await expect(page.locator('#pane-reduction')).toBeHidden();
  await expect(page.locator('#pane-break')).toBeHidden();
  await expect(page.locator('#pane-wall')).toBeHidden();
  await expect(page.locator('#pane-paper')).toBeHidden();
  await expect(page.locator('#kat-verdict')).toHaveAttribute('data-kat', 'pass');
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, [data-theme-toggle]'),
  ).toHaveCount(0);
}

export async function driveAllStates(page: Page, viewportLabel: string): Promise<void> {
  const scanAt = (state: string): Promise<void> => scan(page, `${viewportLabel} / ${state}`);
  await scanAt('arrival with KAT match');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press('Tab');
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  await page.locator('#key-input').fill('00');
  await page.getByRole('button', { name: 'Generate keystream' }).click();
  await expect(page.locator('#cipher-error')).toContainText('exactly 10 bytes');
  await scanAt('invalid short key');

  await page.locator('#key-input').fill('00000000000000000000');
  await page.getByRole('button', { name: 'Generate keystream' }).click();
  await expect(page.locator('#cipher-error')).toBeHidden();

  // Exhibit 5 before any search has run: inert, and a real reachable state.
  await page.getByRole('tab', { name: /The Wall/ }).click();
  await expect(page.locator('#wall-absent')).toBeVisible();
  await expect(page.locator('#wall-absent')).toHaveAttribute('data-rate', 'absent');
  await expect(page.locator('#wall-body')).toBeHidden();
  await scanAt('wall inert with no measured rate');

  // Exhibit 6 needs no rate, so it renders its sourced table from the start.
  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();
  await expect(page.locator('#paper-verdict')).toHaveAttribute('data-claim', 'academically-broken');
  await scanAt('attack table before any rate exists');

  await page.getByRole('tab', { name: /The Reduction/ }).click();
  await expect(page.locator('#pane-reduction')).toBeVisible();
  await scanAt('reduction before loading');
  await page.getByRole('button', { name: 'Load next byte' }).click();
  await expect(page.locator('#trace-body tr')).toHaveCount(1);
  await scanAt('reduction after one byte');
  await page.getByRole('button', { name: 'Run all ten' }).click();
  await expect(page.locator('#trace-body tr')).toHaveCount(10);
  await expect(page.locator('#reduction-verdict')).toHaveAttribute('data-claim', 'ok-and-broken');
  await scanAt('reduction complete with OK-AND-BROKEN verdict');

  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.locator('#plaintext-input').fill('00000000');
  await page.getByRole('button', { name: 'Start real search' }).click();
  await expect(page.locator('#attack-error')).toContainText('nonzero known plaintext');
  await scanAt('all-zero plaintext rejected');

  await page.locator('#plaintext-input').fill('524144494f');
  await page.getByRole('button', { name: 'Start real search' }).click();
  await expect(page.locator('#attack-result')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#attack-result')).toHaveAttribute('data-check', 'pass');
  await scanAt('effective key recovered and independently rechecked');

  await page.locator('#plaintext-input').fill('524144494e');
  await expect(page.locator('#attack-result')).toBeHidden();
  await expect(page.locator('#retired-status')).toBeVisible();
  await scanAt('stale recovery retired after input change');

  await page.getByRole('tab', { name: /The Cipher/ }).click();
  await page.locator('#key-input').fill('00000000000000002100');
  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.locator('#plaintext-input').fill('524144494f');
  await page.getByRole('button', { name: 'Start real search' }).click();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.locator('#attack-status')).toContainText('cancelled cleanly', {
    timeout: 30_000,
  });
  await scanAt('worker search cancelled cleanly');

  // A rate exists by now, because the search above really ran.
  await page.getByRole('tab', { name: /The Wall/ }).click();
  await expect(page.locator('#wall-body')).toBeVisible();
  await expect(page.locator('#wall-verdict')).toHaveAttribute('data-claim', 'wall');
  await scanAt('wall with a measured rate');

  await page.getByRole('radio', { name: 'A GPU farm' }).check();
  await expect(page.locator('#wall-multiplier')).toHaveValue('1000000000');
  await scanAt('wall scaled to a GPU farm');

  await page.locator('#wall-multiplier').fill('1e30');
  await expect(page.locator('#wall-absurd')).toBeVisible();
  await scanAt('wall with an absurd multiplier labelled');

  await page.locator('#wall-multiplier').fill('');
  await expect(page.locator('#wall-assumption')).toContainText('does not hold a usable multiplier');
  await scanAt('wall with an empty multiplier field');

  await page.locator('#wall-multiplier').fill('1');
  await expect(page.locator('#wall-absurd')).toBeHidden();

  await page.getByRole('tab', { name: /Paper vs Practice/ }).click();
  await expect(page.locator('#pane-paper')).toBeVisible();
  await expect(page.locator('#paper-verdict')).toHaveAttribute('data-claim', 'academically-broken');
  await scanAt('published attacks plotted against the brute-force lines');

  await page.locator('.attack-table').scrollIntoViewIfNeeded();
  await scanAt('sourced attack table in view');

  await page.getByRole('tab', { name: /The Cipher/ }).click();
  await page.getByRole('tab', { name: /The Cipher/ }).hover();
  await scanAt('inactive tab hovered');
  await page.getByRole('tab', { name: /The Break/ }).click();
  await page.locator('#plaintext-input').focus();
  await expect(page.locator('#plaintext-input')).toBeFocused();
  await scanAt('plaintext input focused');
}