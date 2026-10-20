import { execFileSync } from 'node:child_process';
import { access, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ensureHugo, root } from './setup-hugo.mjs';

await access(path.join(root, 'themes/flavor/theme.toml')).catch(() => {
  throw new Error('Theme missing. Run: git submodule update --init --recursive');
});
const inputURL = process.env.HUGO_BASEURL || process.env.SITE_URL || process.env.CF_PAGES_URL;
const options = ['--gc', '--minify', '--cleanDestinationDir', '--cacheDir', path.join(root, '.cache/hugo')];
if (inputURL) {
  const url = new URL(inputURL);
  if (!['https:', 'http:'].includes(url.protocol) || url.search || url.hash) throw new Error('Use an HTTP(S) site URL without a query or fragment.');
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  options.push('--baseURL', url.href);
}
// Used only by smoke checks of a GitHub project site under /blog/.
if (process.env.BLOG_OUTPUT_DIR) options.push('--destination', path.resolve(process.env.BLOG_OUTPUT_DIR));
const output = process.env.BLOG_OUTPUT_DIR ? path.resolve(process.env.BLOG_OUTPUT_DIR) : path.join(root, 'public');
execFileSync(await ensureHugo(), options, { cwd: root, stdio: 'inherit' });
const pagefind = path.join(root, 'node_modules/pagefind/lib/runner/bin.cjs');
execFileSync(process.execPath, [pagefind, '--site', output], { cwd: root, stdio: 'inherit' });
await mkdir(output, { recursive: true });
await writeFile(path.join(output, '.nojekyll'), '');
await writeFile(path.join(output, '_headers'), `# Optional: these headers are read by Cloudflare Pages, not GitHub Pages.
/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin

/css/*
  Cache-Control: public, max-age=31536000, immutable

/js/*
  Cache-Control: public, max-age=31536000, immutable

/fonts/*
  Cache-Control: public, max-age=86400

/pagefind/*
  Cache-Control: public, max-age=0, must-revalidate
`);
console.log(`Built static blog and search index in ${path.relative(root, output)}/`);
