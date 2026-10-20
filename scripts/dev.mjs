import { spawn } from 'node:child_process';
import { ensureHugo, root } from './setup-hugo.mjs';

console.log('Draft preview; full-text search is available after npm run build && npm run preview.');
const child = spawn(await ensureHugo(), ['server', '--buildDrafts', '--bind', '127.0.0.1', '--port', '1313', '--disableFastRender', ...process.argv.slice(2)], { cwd: root, stdio: 'inherit' });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('exit', code => process.exit(code ?? 0));
