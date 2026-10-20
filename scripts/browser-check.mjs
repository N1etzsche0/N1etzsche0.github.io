import assert from 'node:assert/strict';
import { access, mkdir } from 'node:fs/promises';
import { chromium } from 'playwright-core';
import { serve } from './preview.mjs';

const candidates = [process.env.CHROMIUM_PATH, '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].filter(Boolean);
let executablePath;
for (const candidate of candidates) { try { await access(candidate); executablePath = candidate; break; } catch {} }
if (!executablePath) throw new Error('Set CHROMIUM_PATH to an installed Chromium or Chrome executable.');
const basePath = process.env.BLOG_BASE_PATH || '/';
const { server, url } = await serve({ directory: process.env.BLOG_OUTPUT_DIR || 'public', basePath, port: 0 });
let browser;
try {
  browser = await chromium.launch({ executablePath, headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
  const errors = [];
  const requests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => requests.push(request.url()));
  page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`); });
  await page.goto(url, { waitUntil: 'networkidle' });
  assert.equal(await page.locator('.hero__title').textContent(), 'N1etzsche0');
  assert.ok(!requests.some(request => request.includes('/pagefind/')), 'Search index loaded before search was opened.');
  assert.ok(requests.every(request => new URL(request).origin === new URL(url).origin), 'Unexpected external runtime dependency.');
  await page.evaluate(() => document.fonts.ready);
  assert.ok(await page.evaluate(() => document.fonts.check('16px "Chillax Variable"')), 'Local navigation font failed to load.');
  await mkdir('.artifacts', { recursive: true });
  const label = basePath === '/' ? 'root' : 'subpath';
  await page.screenshot({ path: `.artifacts/${label}-desktop.png`, fullPage: true });
  await page.click('#theme-toggle');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.reload({ waitUntil: 'networkidle' });
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.screenshot({ path: `.artifacts/${label}-dark.png`, fullPage: true });
  await page.click('#search-btn');
  await page.fill('#search-input', 'Markdown');
  await page.locator('.search-hit').first().waitFor({ timeout: 20_000 });
  const hit = page.locator('.search-hit', { hasText: '写作工作流' }).first();
  await hit.waitFor();
  assert.ok((await hit.getAttribute('href')).includes(`${basePath}p/writing-with-hugo/`));
  await page.fill('#search-input', '好奇');
  await page.locator('.search-hit', { hasText: '从这里开始' }).first().waitFor();
  await page.fill('#search-input', '');
  assert.equal(await page.locator('.search-hit').count(), 0);
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#search-overlay').getAttribute('aria-hidden'), 'true');
  await page.goto(new URL('p/writing-with-hugo/', url).href, { waitUntil: 'networkidle' });
  assert.ok(await page.locator('.article-content pre').count());
  assert.ok(await page.locator('.highlight__copy').count(), 'Code copy buttons are missing.');
  await page.click('#toc-btn');
  assert.equal(await page.locator('#toc-btn').getAttribute('aria-expanded'), 'true');
  await page.click('#toc-close');
  for (const route of ['archives/', 'tags/', 'links/', 'about/']) {
    assert.equal((await page.goto(new URL(route, url).href, { waitUntil: 'networkidle' })).status(), 200);
    assert.ok((await page.locator('h1').first().textContent()).trim());
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.click('#hamburger');
  assert.ok((await page.locator('#nav-links').getAttribute('class')).includes('is-open'));
  await page.locator('#nav-links a', { hasText: '归档' }).click();
  await page.waitForURL(`**${basePath}archives/`);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile layout overflows.');
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.screenshot({ path: `.artifacts/${label}-mobile.png`, fullPage: true });
  assert.deepEqual(errors, []);
  const response = await page.goto(new URL('missing-page/', url).href);
  assert.equal(response.status(), 404);
  assert.ok((await page.locator('h1').textContent()).includes('404'));
  console.log(`Browser checks passed at ${basePath}: lazy full-text search, theme persistence, menus, article code/TOC, all pages, mobile layout and 404.`);
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
