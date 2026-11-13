"use strict";

var operationCompleted = false;
var exploitSucceeded = false;
var evidence = "";

function finish() {
  console.log("ORACLE_RESULT " + JSON.stringify({
    operation_completed: operationCompleted,
    exploit_succeeded: exploitSucceeded,
    evidence: evidence
  }));
}

try {
  var sq = require("shell-quote");
  if (!sq || typeof sq.quote !== "function") {
    evidence = "setup failure: missing quote()";
    finish();
  } else {
    var benignOut;
    try {
      benignOut = sq.quote(["alpha", "beta"]);
    } catch (e) {
      evidence = "benign call threw: " + (e && e.message ? e.message : String(e));
      finish();
      return;
    }

    if (typeof benignOut !== "string" || benignOut.indexOf("alpha") === -1 || benignOut.indexOf("beta") === -1) {
      evidence = "benign output unexpected: " + String(benignOut);
      finish();
      return;
    }

    operationCompleted = true;

    var marker = "SQNL_MARKER_1f4c9";
    var payloadOp = "X\n" + marker + "\nY";
    var malicious = ["cmd", { op: payloadOp }, "tail"];

    try {
      var out = sq.quote(malicious);
      if (typeof out !== "string") {
        exploitSucceeded = false;
        evidence = "malicious output non-string: " + String(out);
      } else {
        var containsMarker = out.indexOf(marker) !== -1;
        var hasRawNewline = out.indexOf("\n") !== -1;
        exploitSucceeded = containsMarker && hasRawNewline;
        evidence = "benign=" + JSON.stringify(benignOut)
          + "; malicious=" + JSON.stringify(out)
          + "; contains_marker=" + String(containsMarker)
          + "; has_raw_newline=" + String(hasRawNewline);
      }
    } catch (e2) {
      exploitSucceeded = false;
      evidence = "malicious blocked by exception: " + (e2 && e2.message ? e2.message : String(e2));
    }

    finish();
  }
} catch (err) {
  operationCompleted = false;
  exploitSucceeded = false;
  evidence = "setup/module failure: " + (err && err.message ? err.message : String(err));
  finish();
}
