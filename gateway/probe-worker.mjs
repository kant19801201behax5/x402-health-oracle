import { parentPort } from 'node:worker_threads';

// Deterministic micro-workload — mirrors src/services/jitterProbe.ts microWorkload
// (which is unit-tested). Timing THIS captures real CPU/scheduler/cache jitter.
// The old probe timed two adjacent hrtime.bigint() calls with nothing between them,
// so every delta was just call overhead — near-constant, no physical signal.
function microWorkload(rounds) {
  let acc = 0 >>> 0;
  for (let i = 0; i < rounds; i++) {
    acc = (acc + ((i * 2654435761) >>> 0)) >>> 0;
    acc ^= acc >>> 13;
    acc = (acc * 5) >>> 0;
  }
  return acc >>> 0;
}

function startProbe() {
  const integrityCheck = () => {
    // eBPF LSM-hook simulation: verify the probe's own source wasn't tampered with.
    const source = startProbe.toString();
    if (source.length < 300 || !source.includes('hrtime')) {
      parentPort?.postMessage({ type: 'INTEGRITY_FAIL' });
    }
  };

  let sink = 0 >>> 0; // consume the workload result so the JIT can't elide the loop

  setInterval(() => {
    integrityCheck();
    const samples = 100;
    const deltas = [];

    for (let i = 0; i < samples; i++) {
      const start = process.hrtime.bigint();
      sink = (sink ^ microWorkload(256)) >>> 0; // real work — timing carries the jitter
      const end = process.hrtime.bigint();
      deltas.push(Number(end - start));
    }

    if (parentPort) {
      parentPort.postMessage({ type: 'JITTER_DATA', deltas, sink });
    }
  }, 200);
}

startProbe();
