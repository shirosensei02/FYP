'use strict';
// Preloaded (node --require) only when the locked oracle runs against a generated
// patch. It records which package functions reached process, file or network
// sinks, so a failed patch can be told where the exploit still gets through.
// Every step is guarded: tracing must never change what the oracle reports.
try {
  const fs = require('fs');
  const childProcess = require('child_process');

  const KEEP_EVENTS = 8;
  const MAX_FRAMES = 6;
  const MAX_ARGUMENT = 160;
  const events = new Map();

  function packageFrames() {
    const previousLimit = Error.stackTraceLimit;
    Error.stackTraceLimit = 40;
    const stack = String(new Error().stack || '').split('\n').slice(1);
    Error.stackTraceLimit = previousLimit;
    const frames = [];
    for (const line of stack) {
      if (!line.includes('node_modules') || line.includes('oracle-sink-trace')) continue;
      frames.push(line.trim().replace(/^at\s+/, '').replace(/[^\s()]*node_modules[\\/]/g, ''));
      if (frames.length >= MAX_FRAMES) break;
    }
    return frames;
  }

  function record(sink, args) {
    const frames = packageFrames();
    if (!frames.length) return;
    const argument = String(args[0]).slice(0, MAX_ARGUMENT);
    const key = frames[0] + '|' + argument;
    // exec() calls execFile() internally; keep the sink the package itself called.
    const event = events.get(key) || { sink, argument, frames };
    // Later calls are the exploit; earlier ones are the benign warm-up.
    events.delete(key);
    events.set(key, event);
    if (events.size > KEEP_EVENTS) events.delete(events.keys().next().value);
  }

  function wrap(target, names, prefix) {
    for (const name of names) {
      const original = target[name];
      if (typeof original !== 'function') continue;
      const wrapper = function (...args) {
        try { record(prefix + name, args); } catch (_) { /* tracing is best effort */ }
        return original.apply(this, args);
      };
      // util.promisify.custom and similar symbols must survive the wrapping.
      for (const key of Reflect.ownKeys(original)) {
        if (key === 'length' || key === 'name' || key === 'prototype') continue;
        try { Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(original, key)); } catch (_) { /* ignore */ }
      }
      target[name] = wrapper;
    }
  }

  wrap(childProcess, ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'], 'child_process.');
  wrap(fs, [
    'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream',
    'readFile', 'readFileSync', 'createReadStream', 'open', 'openSync',
    'unlink', 'unlinkSync', 'rename', 'renameSync', 'mkdir', 'mkdirSync', 'rmSync',
  ], 'fs.');

  process.on('exit', () => {
    try {
      for (const event of events.values()) {
        fs.writeSync(2, '\nSINK_TRACE ' + JSON.stringify(event) + '\n');
      }
    } catch (_) { /* ignore */ }
  });
} catch (_) { /* never break the oracle */ }
