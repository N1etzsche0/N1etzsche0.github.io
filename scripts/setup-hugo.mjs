import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = fileURLToPath(new URL('../', import.meta.url));
export const version = (await readFile(new URL('../.hugo-version', import.meta.url), 'utf8')).trim();
const executable = path.join(root, '.tools', 'hugo', process.platform === 'win32' ? 'hugo.exe' : 'hugo');

function matches(command) {
  try {
    const output = execFileSync(command, ['version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return Boolean((output.split(/\s+/)[1]?.startsWith(`v${version}-`) && output.includes('+extended')) || output.includes(`v${version}+extended`));
  } catch { return false; }
}

async function download(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(120_000) });
  if (!response.ok) throw new Error(`Download failed (${response.status}): ${url}`);
  return Buffer.from(await response.arrayBuffer());
}

export async function ensureHugo() {
  if (matches(executable)) return executable;
  if (matches('hugo')) return 'hugo';
  const platforms = { linux: 'linux', win32: 'windows' };
  const architectures = { x64: 'amd64', arm64: 'arm64' };
  const platform = platforms[process.platform];
  const arch = architectures[process.arch];
  if (!platform || !arch) throw new Error(`Install Hugo Extended ${version} for ${process.platform}/${process.arch} from https://github.com/gohugoio/hugo/releases/tag/v${version}.`);
  const filename = `hugo_extended_${version}_${platform}-${arch}.${process.platform === 'win32' ? 'zip' : 'tar.gz'}`;
  const releaseURL = `https://github.com/gohugoio/hugo/releases/download/v${version}`;
  console.log(`Installing Hugo Extended ${version} into .tools/hugo/ …`);
  const [archive, checksums] = await Promise.all([
    download(`${releaseURL}/${filename}`),
    download(`${releaseURL}/hugo_${version}_checksums.txt`),
  ]);
  const expected = checksums.toString().split(/\r?\n/).find(line => line.trim().endsWith(` ${filename}`))?.trim().split(/\s+/)[0];
  const actual = createHash('sha256').update(archive).digest('hex');
  if (!expected || actual !== expected) throw new Error(`SHA-256 verification failed for ${filename}.`);
  await mkdir(path.dirname(executable), { recursive: true });
  const archivePath = path.join(root, '.tools', filename);
  await writeFile(archivePath, archive);
  try {
    if (process.platform === 'win32') {
      execFileSync('tar', ['-xf', archivePath, '-C', path.dirname(executable), 'hugo.exe'], { stdio: 'inherit' });
    } else {
      execFileSync('tar', ['-xzf', archivePath, '-C', path.dirname(executable), 'hugo'], { stdio: 'inherit' });
      await chmod(executable, 0o755);
    }
  } finally { await rm(archivePath, { force: true }); }
  if (!matches(executable)) throw new Error('Installed Hugo did not pass the version check.');
  return executable;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(execFileSync(await ensureHugo(), ['version'], { encoding: 'utf8' }).trim());
}
