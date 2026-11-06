import assert from 'node:assert/strict';
import { access, mkdir, readFile } from 'node:fs/promises';
import { chromium } from 'playwright-core';
import { serve } from './preview.mjs';

const candidates = [process.env.CHROMIUM_PATH, '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].filter(Boolean);
let executablePath;
for (const candidate of candidates) { try { await access(candidate); executablePath = candidate; break; } catch {} }
if (!executablePath) throw new Error('Set CHROMIUM_PATH to an installed Chromium or Chrome executable.');
const basePath = process.env.BLOG_BASE_PATH || '/';
const paletteSource = await readFile('themes/flavor/assets/scss/_variables.scss', 'utf8');
const palettes = Object.fromEntries([...paletteSource.matchAll(/html\[data-theme="(light|dark)"\]\s*\{([^}]+)\}/g)].map(([, theme, rules]) => [theme,
  Object.fromEntries([...rules.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map(([, key, value]) => [key, value.trim()]))
]));
const { server, url } = await serve({ directory: process.env.BLOG_OUTPUT_DIR || 'public', basePath, port: 0 });
let browser;
try {
  browser = await chromium.launch({ executablePath, headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
  const page = await context.newPage();
  const errors = [];
  const requests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => requests.push(request.url()));
  page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`); });
  await page.goto(url, { waitUntil: 'networkidle' });
  const checkPalette = async theme => {
    const actual = await page.evaluate(keys => Object.fromEntries(keys.map(key => [key, getComputedStyle(document.documentElement).getPropertyValue(key).trim()])), Object.keys(palettes[theme]));
    assert.deepEqual(actual, palettes[theme], `The original Flavor ${theme} palette must be preserved.`);
    assert.ok(await page.locator('.navbar').evaluate(element => getComputedStyle(element).backgroundImage.includes('linear-gradient')), 'Original navigation gradient is missing.');
  };
  await checkPalette('light');
  assert.equal(await page.locator('.hero__title').textContent(), '疏狂');
  assert.ok(!requests.some(request => request.includes('/pagefind/')), 'Search index loaded before search was opened.');
  assert.ok(requests.every(request => new URL(request).origin === new URL(url).origin), 'Unexpected external runtime dependency.');
  const homeAvatar = await page.locator('.hero__avatar').getAttribute('src');
  assert.ok(homeAvatar.endsWith('/img/avatar.svg'));
  const avatarSvg = await (await page.request.get(new URL(homeAvatar, url).href)).text();
  const embeddedAvatar = avatarSvg.match(/data:image\/webp;base64,([^"\s]+)/)?.[1];
  assert.ok(embeddedAvatar, 'The homepage avatar must contain the locally built GitHub image.');
  assert.equal(await page.locator('link[rel="icon"][sizes="32x32"]').count(), 1);
  const aboutTab = await context.newPage();
  await aboutTab.goto(new URL('about/', url).href, { waitUntil: 'networkidle' });
  const aboutAvatar = await aboutTab.locator('.about-profile__avatar').getAttribute('src');
  const aboutBytes = await (await page.request.get(new URL(aboutAvatar, url).href)).body();
  assert.deepEqual(Buffer.from(embeddedAvatar, 'base64'), aboutBytes, 'Home and about must use the same avatar.');
  await aboutTab.close();
  await page.evaluate(() => document.fonts.ready);
  assert.ok(await page.evaluate(() => document.fonts.check('16px "Chillax Variable"')), 'Local navigation font failed to load.');
  await mkdir('.artifacts', { recursive: true });
  const label = basePath === '/' ? 'root' : 'subpath';
  await page.screenshot({ path: `.artifacts/${label}-desktop.png`, fullPage: true });
  await page.click('#theme-toggle');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await checkPalette('dark');
  await page.reload({ waitUntil: 'networkidle' });
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  const secondTab = await page.context().newPage();
  await secondTab.goto(url, { waitUntil: 'networkidle' });
  assert.equal(await secondTab.locator('html').getAttribute('data-theme'), 'dark', 'Theme choice should persist in a new tab.');
  await secondTab.close();
  await page.screenshot({ path: `.artifacts/${label}-dark.png`, fullPage: true });
  await page.click('#search-btn');
  await page.fill('#search-input', 'Fileury');
  await page.locator('.search-hit').first().waitFor({ timeout: 20_000 });
  const hit = page.locator('.search-hit', { hasText: 'ALICTF 2026' }).first();
  await hit.waitFor();
  assert.ok((await hit.getAttribute('href')).includes(`${basePath}p/alictf-2026-writeup/`));
  await page.fill('#search-input', 'maybe_easy');
  await page.locator('.search-hit', { hasText: 'RCTF 2025' }).first().waitFor();
  await page.fill('#search-input', '');
  assert.equal(await page.locator('.search-hit').count(), 0);
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#search-overlay').getAttribute('aria-hidden'), 'true');
  assert.equal(await page.locator('#search-overlay').evaluate(element => element.inert), true);
  assert.equal(await page.locator('#search-btn').evaluate(element => element === document.activeElement), true);
  await page.keyboard.press('Control+k');
  assert.equal(await page.locator('#search-input').evaluate(element => element === document.activeElement), true);
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.locator('#search-close').evaluate(element => element === document.activeElement), true, 'Search focus must stay in the dialog.');
  await page.click('#search-close');
  assert.equal(await page.locator('#search-overlay').getAttribute('aria-hidden'), 'true');
  await page.goto(new URL('p/alictf-2026-writeup/', url).href, { waitUntil: 'networkidle' });
  assert.ok(await page.locator('.article-content pre').count());
  assert.ok(await page.locator('.highlight__copy').count(), 'Code copy buttons are missing.');
  assert.equal(await page.locator('#toc-aside').evaluate(element => element.inert), false);
  await page.waitForFunction(() => document.querySelector('#toc-aside .toc a')?.getAttribute('aria-current') === 'location');
  const secondTocLink = page.locator('#toc-aside .toc a').nth(1);
  await secondTocLink.click();
  await page.waitForFunction(() => document.querySelectorAll('#toc-aside .toc a')[1]?.getAttribute('aria-current') === 'location');
  await page.click('#toc-btn');
  assert.equal(await page.locator('#toc-aside').evaluate(element => element.inert), true, 'Hidden directory links must not receive keyboard focus.');
  await page.click('#toc-btn');
  assert.equal(await page.locator('#toc-btn').getAttribute('aria-expanded'), 'true');
  assert.equal(await page.locator('#toc-aside').evaluate(element => element.inert), false);
  await page.click('#toc-btn');
  assert.equal(await page.locator('#toc-aside').evaluate(element => element.inert), true);
  assert.equal(await page.locator('#toc-btn').evaluate(element => element === document.activeElement), true);
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(url).origin });
  const copy = page.locator('.highlight__copy').first();
  const expectedCode = await page.locator('.article-content pre code').first().textContent();
  await copy.click();
  await page.waitForFunction(() => document.querySelector('.highlight__copy').textContent.includes('已复制'));
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), expectedCode, 'Copy must include only code, without toolbar or line numbers.');
  await page.evaluate(() => { navigator.clipboard.writeText = async () => { throw new DOMException('Clipboard blocked', 'NotAllowedError'); }; });
  await copy.click();
  await page.waitForFunction(() => document.querySelector('.highlight__copy').textContent.includes('复制失败'));
  assert.equal(await copy.isEnabled(), true, 'A clipboard denial must allow retrying.');
  const anchor = page.locator('.heading-anchor').first();
  await anchor.focus();
  await anchor.click();
  await page.waitForFunction(() => { const top = document.querySelector('.article-content h2').getBoundingClientRect().top; return top >= 70 && top <= 130; });
  await page.evaluate(() => scrollTo({ top: document.body.scrollHeight, behavior: 'instant' }));
  await page.waitForFunction(() => getComputedStyle(document.getElementById('reading-progress')).transform === 'matrix(1, 0, 0, 1, 0, 0)');
  await page.setViewportSize({ width: 820, height: 900 });
  const articleWidth = await page.locator('.read').evaluate(element => element.getBoundingClientRect().width);
  await page.click('#toc-btn');
  assert.equal(await page.locator('#toc-aside').getAttribute('aria-modal'), 'true');
  assert.equal(await page.locator('.read').evaluate(element => element.inert), true);
  assert.equal(await page.locator('.read').evaluate(element => element.getBoundingClientRect().width), articleWidth, 'A tablet directory must preserve the reading width.');
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.locator('#toc-aside .toc a').last().evaluate(element => element === document.activeElement), true, 'Directory focus must stay inside the modal.');
  const targetHash = await page.locator('#toc-aside .toc a').nth(1).getAttribute('href');
  await page.locator('#toc-aside .toc a').nth(1).click();
  assert.equal(await page.locator('#toc-aside').getAttribute('aria-hidden'), 'true');
  assert.equal(await page.locator('.read').evaluate(element => element.inert), false);
  await page.waitForFunction(hash => document.getElementById(decodeURIComponent(hash.slice(1))) === document.activeElement, targetHash);
  await page.click('#toc-btn');
  await page.locator('.toc-backdrop').click({ position: { x: 10, y: 100 } });
  assert.equal(await page.locator('#toc-btn').getAttribute('aria-expanded'), 'false');
  await page.click('#toc-btn');
  await page.setViewportSize({ width: 1440, height: 1000 });
  assert.equal(await page.locator('.read').evaluate(element => element.inert), false);
  assert.equal(await page.locator('#toc-aside').getAttribute('aria-modal'), null);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.keyboard.press('Control+k');
  assert.equal(await page.locator('#toc-btn').getAttribute('aria-expanded'), 'false', 'Opening search must close the directory and restore its background.');
  assert.equal(await page.locator('#search-input').evaluate(element => element === document.activeElement), true);
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('.read').evaluate(element => element.inert), false);
  for (const route of ['archives/', 'tags/', 'links/', 'about/']) {
    assert.equal((await page.goto(new URL(route, url).href, { waitUntil: 'networkidle' })).status(), 200);
    assert.ok((await page.locator('h1').first().textContent()).trim());
  }
  const linkOrders = [];
  for (const random of [0, 0.999999]) {
    const linksPage = await context.newPage();
    await linksPage.addInitScript(value => { Math.random = () => value; }, random);
    await linksPage.goto(new URL('links/', url).href, { waitUntil: 'networkidle' });
    const order = () => linksPage.locator('[data-links-grid]').evaluateAll(grids => grids.map(grid => [...grid.querySelectorAll('[data-links-card]')].map(card => card.dataset.name)));
    const desktop = await order();
    await linksPage.setViewportSize({ width: 390, height: 844 });
    await linksPage.waitForTimeout(200);
    assert.deepEqual(await order(), desktop, 'Resizing should preserve the shuffled order.');
    linkOrders.push(desktop);
    await linksPage.close();
  }
  assert.ok(linkOrders[0].some(group => group.length > 1), 'The links page needs a group with multiple cards.');
  assert.notDeepEqual(linkOrders[0], linkOrders[1], 'Different random choices should produce different link orders.');
  assert.deepEqual(linkOrders[0].map(group => [...group].sort()), linkOrders[1].map(group => [...group].sort()), 'Shuffling must keep all cards in their original groups.');
  const scrollPage = await context.newPage();
  await scrollPage.goto(new URL('p/rctf-2025-writeup/', url).href, { waitUntil: 'domcontentloaded' });
  await scrollPage.evaluate(() => {
    const article = document.querySelector('.article-content');
    for (const [id, value] of [['wheel-short', 'short code'], ['wheel-tall', Array(100).fill('a short line').join('\n')], ['wheel-wide', 'a'.repeat(500)]].reverse()) {
      const pre = document.createElement('pre');
      pre.id = id;
      const code = document.createElement('code');
      code.textContent = value;
      pre.append(code);
      article.prepend(pre);
    }
    document.dispatchEvent(new CustomEvent('flavor:enhance', { detail: article }));
  });
  const aimAt = async selector => {
    const pre = scrollPage.locator(selector);
    await pre.evaluate(element => element.scrollIntoView({ block: 'center', behavior: 'instant' }));
    const bounds = await pre.boundingBox();
    await scrollPage.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
    return pre;
  };
  const shortCode = await aimAt('#wheel-short');
  assert.equal(await shortCode.evaluate(element => element.scrollHeight <= element.clientHeight && element.scrollWidth <= element.clientWidth), true);
  let pageY = await scrollPage.evaluate(() => scrollY);
  await scrollPage.mouse.wheel(0, 180);
  await scrollPage.waitForFunction(previous => scrollY > previous, pageY);
  const tallCode = await aimAt('#wheel-tall');
  await tallCode.evaluate(element => { element.scrollTop = 0; });
  await scrollPage.mouse.wheel(0, 180);
  await scrollPage.waitForFunction(() => document.querySelector('#wheel-tall').scrollTop > 0);
  const down = await tallCode.evaluate(element => element.scrollTop);
  await scrollPage.mouse.wheel(0, -90);
  await scrollPage.waitForFunction(previous => document.querySelector('#wheel-tall').scrollTop < previous, down);
  await tallCode.evaluate(element => { element.scrollTop = element.scrollHeight; });
  pageY = await scrollPage.evaluate(() => scrollY);
  await scrollPage.mouse.wheel(0, 180);
  await scrollPage.waitForFunction(previous => scrollY > previous, pageY);
  const wideCode = await aimAt('#wheel-wide');
  assert.equal(await wideCode.evaluate(element => element.scrollWidth > element.clientWidth && element.scrollHeight <= element.clientHeight), true);
  pageY = await scrollPage.evaluate(() => scrollY);
  await scrollPage.mouse.wheel(0, 100);
  await scrollPage.waitForFunction(previous => scrollY > previous, pageY);
  await aimAt('#wheel-wide');
  await scrollPage.mouse.wheel(180, 0);
  await scrollPage.waitForFunction(() => document.querySelector('#wheel-wide').scrollLeft > 0);
  assert.equal(await tallCode.getAttribute('aria-label'), '代码，可纵向滚动');
  assert.equal(await wideCode.getAttribute('aria-label'), '代码，可横向滚动');
  await scrollPage.close();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.click('#hamburger');
  assert.ok((await page.locator('#nav-links').getAttribute('class')).includes('is-open'));
  assert.equal(await page.locator('#hamburger').getAttribute('aria-expanded'), 'true');
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#hamburger').getAttribute('aria-expanded'), 'false');
  assert.equal(await page.locator('#hamburger').evaluate(element => element === document.activeElement), true);
  await page.click('#hamburger');
  await page.locator('.site-footer__copy').click();
  assert.equal(await page.locator('#hamburger').getAttribute('aria-expanded'), 'false', 'Outside click should close the mobile menu.');
  await page.click('#hamburger');
  await page.locator('#nav-links a', { hasText: '归档' }).click();
  await page.waitForURL(`**${basePath}archives/`);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile layout overflows.');
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.screenshot({ path: `.artifacts/${label}-mobile.png`, fullPage: true });
  assert.deepEqual(errors, []);
  const response = await page.goto(new URL('missing-page/', url).href);
  assert.equal(response.status(), 404);
  assert.ok((await page.locator('h1').textContent()).includes('404'));
  const blocked = await browser.newContext({ viewport: { width: 390, height: 844 }, colorScheme: 'light' });
  await blocked.addInitScript(() => {
    for (const name of ['localStorage', 'sessionStorage']) Object.defineProperty(window, name, { get() { throw new DOMException('Storage blocked', 'SecurityError'); } });
  });
  const restricted = await blocked.newPage();
  const storageErrors = [];
  restricted.on('pageerror', error => storageErrors.push(error.message));
  await restricted.goto(url, { waitUntil: 'networkidle' });
  await restricted.click('#theme-toggle');
  assert.equal(await restricted.locator('html').getAttribute('data-theme'), 'dark');
  await restricted.click('#hamburger');
  assert.equal(await restricted.locator('#hamburger').getAttribute('aria-expanded'), 'true');
  assert.deepEqual(storageErrors, [], 'Blocked browser storage must not break theme or navigation.');
  await blocked.close();
  for (const [slug, headings] of [
    ['alictf-2026-writeup', ['Fileury', 'MHGA']],
    ['rctf-2025-writeup', ['RootKB', 'RootKB–', 'maybe_easy']],
  ]) {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(new URL(`p/${slug}/`, url).href, { waitUntil: 'networkidle' });
    assert.equal(await page.locator('#toc-aside').getAttribute('aria-hidden'), 'false');
    assert.equal(await page.locator('#toc-aside').evaluate(element => element.inert), false);
    const bounds = await page.evaluate(() => ({
      article: document.querySelector('.read').getBoundingClientRect().right,
      toc: document.querySelector('#toc-aside').getBoundingClientRect().left,
    }));
    assert.ok(bounds.article <= bounds.toc + 1, 'The desktop directory must not cover the article.');
    if (slug === 'alictf-2026-writeup') {
      for (const width of [1200, 1280, 1440, 1920]) {
        await page.setViewportSize({ width, height: 900 });
        await page.waitForTimeout(250);
        const layout = await page.evaluate(() => ({
          article: document.querySelector('.read').getBoundingClientRect().toJSON(),
          header: document.querySelector('.post-single__header').getBoundingClientRect().toJSON(),
          toc: document.querySelector('#toc-aside').getBoundingClientRect().toJSON(),
          pageWidth: document.documentElement.scrollWidth,
        }));
        assert.ok(layout.article.width > 800, `Article should use more space at ${width}px.`);
        assert.ok(layout.article.right <= layout.toc.left + 1, `Directory covers the article at ${width}px.`);
        assert.ok(Math.abs(layout.header.width - (layout.article.width - 48)) < 2, 'Article header should use the available content width.');
        assert.ok(layout.pageWidth <= width, `Page overflows at ${width}px.`);
      }
    }
    for (const heading of headings) assert.equal(await page.locator('#toc-aside .toc a').getByText(heading, { exact: true }).count(), 1);
    if (slug === 'rctf-2025-writeup') {
      const code = page.locator('.article-content pre').first();
      assert.ok(await code.evaluate(element => element.scrollHeight > element.clientHeight), 'Long code samples must scroll inside their panel.');
    }
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.locator('#toc-aside').getAttribute('aria-hidden'), 'true');
    await page.click('#toc-btn');
    assert.equal(await page.locator('#toc-aside').getAttribute('aria-modal'), 'true');
    await page.locator('#toc-aside .toc a').getByText(headings[0], { exact: true }).click();
    assert.equal(await page.locator('#toc-aside').getAttribute('aria-hidden'), 'true');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  }
  console.log(`Browser checks passed at ${basePath}: original palettes, lazy search, keyboard focus, theme across tabs, blocked storage, mobile menus, clipboard success/denial, article links/progress, responsive directory, all pages and 404.`);
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
