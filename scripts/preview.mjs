import http from 'node:http';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.png': 'image/png', '.jpg': 'image/jpeg', '.xml': 'application/xml', '.txt': 'text/plain', '.woff2': 'font/woff2', '.wasm': 'application/wasm' };

export async function serve({ directory = 'public', port = 1313, basePath = '/' } = {}) {
  const root = path.resolve(directory);
  const server = http.createServer(async (request, response) => {
    try {
      const urlPath = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
      if (basePath !== '/' && urlPath === basePath.slice(0, -1)) {
        response.writeHead(301, { Location: basePath }); response.end(); return;
      }
      if (!urlPath.startsWith(basePath)) { response.writeHead(404); response.end(); return; }
      let file = path.resolve(root, `.${'/' + urlPath.slice(basePath.length)}`);
      if (file !== root && !file.startsWith(root + path.sep)) { response.writeHead(403); response.end(); return; }
      let status = 200;
      try {
        const info = await stat(file);
        if (info.isDirectory()) {
          if (!urlPath.endsWith('/')) { response.writeHead(301, { Location: urlPath + '/' }); response.end(); return; }
          file = path.join(file, 'index.html');
        }
        await stat(file);
      } catch { status = 404; file = path.join(root, '404.html'); }
      response.writeHead(status, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      createReadStream(file).on('error', () => response.destroy()).pipe(response);
    } catch { response.writeHead(400); response.end(); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { server, url: `http://127.0.0.1:${server.address().port}${basePath}` };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { url } = await serve({ directory: process.env.BLOG_OUTPUT_DIR || 'public', port: Number(process.env.PORT || 1313), basePath: process.env.BLOG_BASE_PATH || '/' });
  console.log(`Local: ${url}`);
}
