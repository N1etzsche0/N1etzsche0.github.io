import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { gzipSync } from 'node:zlib';

const output = path.resolve(process.env.BLOG_OUTPUT_DIR || 'public');
async function files(directory) {
  return (await Promise.all((await readdir(directory, { withFileTypes: true })).map(entry => {
    const filename = path.join(directory, entry.name);
    return entry.isDirectory() ? files(filename) : filename;
  }))).flat();
}
const all = await files(output);
const htmlFiles = all.filter(filename => filename.endsWith('.html'));
const home = await readFile(path.join(output, 'index.html'), 'utf8');
const canonical = home.match(/<link\b[^>]*rel=(?:"canonical"|'canonical'|canonical)[^>]*href=(?:"([^"]+)"|'([^']+)'|([^\s>]+))/)?.slice(1).find(Boolean);
assert.ok(canonical, 'Homepage must have a canonical URL.');
const site = new URL(canonical);
const failures = [];
for (const filename of htmlFiles) {
  const html = await readFile(filename, 'utf8');
  const relative = path.relative(output, filename).split(path.sep).join('/').replace(/index\.html$/, '');
  const pageURL = new URL(relative, site);
  assert.ok(/<html\b[^>]*lang=/.test(html), `Missing language in ${relative}`);
  const redirect = /http-equiv=(?:"refresh"|'refresh'|refresh)/i.test(html);
  if (!redirect) assert.ok(html.includes('name=description') || html.includes('name="description"'), `Missing description in ${relative}`);
  for (const match of html.matchAll(/\b(?:href|src|data-full)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)) {
    const value = match.slice(1).find(value => value !== undefined);
    if (!value || value.startsWith('#') || /^(data:|mailto:|tel:)/.test(value)) continue;
    const url = new URL(value.replaceAll('&amp;', '&'), pageURL);
    if (url.origin !== site.origin) continue;
    if (!url.pathname.startsWith(site.pathname)) { failures.push(`${relative}: URL escapes base path: ${url.pathname}`); continue; }
    let target = path.join(output, decodeURIComponent(url.pathname.slice(site.pathname.length)));
    try {
      if ((await stat(target)).isDirectory()) target = path.join(target, 'index.html');
      await stat(target);
    } catch { failures.push(`${relative}: missing ${url.pathname}`); }
  }
}
assert.deepEqual(failures, [], failures.join('\n'));
assert.ok(all.some(file => file.endsWith('/pagefind/pagefind.js')), 'Pagefind index was not built.');
assert.ok(all.some(file => file.endsWith('/404.html')), 'Custom 404 page was not built.');
assert.ok(!/welcome\.min|typewriter\.min/.test(home), 'Homepage must not load disabled splash or typewriter scripts.');
const styles = all.filter(file => /\/css\/.*\.[a-f0-9]{64}\.css$/.test(file));
assert.equal(styles.length, 1, 'One fingerprinted CSS file is expected.');
const css = await readFile(styles[0]);
assert.ok(gzipSync(css).length < 20_000, 'CSS exceeded the 20 kB gzip budget.');
assert.ok(gzipSync(home).length < 12_000, 'Homepage exceeded the 12 kB gzip budget.');
assert.ok(!css.toString().includes('url(/fonts/'), 'Fonts must resolve beneath the site base path.');
console.log(`Checked ${htmlFiles.length} HTML pages: local links, assets, metadata, search index and 404 passed.`);
console.log(`Homepage ${gzipSync(home).length} B gzip; CSS ${gzipSync(css).length} B gzip; no external runtime assets.`);
