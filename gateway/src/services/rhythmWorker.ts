// src/services/rhythmWorker.ts
// L6: Micro-Precision Physical Probe (Atomics.wait + Cache/RAM Side-Channels)
// Provides sub-millisecond jitter and memory latency measurements.

self.onmessage = (e) => {
  if (e.data.type === 'measure') {
    const { delayUs, iterations, sab } = e.data;
    const results: number[] = [];
    const ramDna: number[] = []; // Software PUF metrics
    
    // Test 1: High-Precision Jitter
    for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        if (sab) {
            const int32 = new Int32Array(sab);
            Atomics.wait(int32, 0, 0, delayUs / 1000); 
        } else {
            const endWait = start + (delayUs / 1000);
            while(performance.now() < endWait) {}
        }
        const end = performance.now();
        results.push((end - start) * 1000); // us
    }

    // Test 2: Software PUF (RAM Latency Fingerprint)
    // We measure the time to traverse a large array with random strides
    // to bypass cache and measure raw RAM/Memory Controller latency DNA.
    const bufferSize = 1024 * 1024; // 1MB to ensure we bust small caches
    const testBuffer = new Uint32Array(bufferSize);
    for (let j = 0; j < 5; j++) {
        const mStart = performance.now();
        // Linear vs Random access pattern comparison
        for (let k = 0; k < 10000; k++) {
            const idx = (k * 167) % bufferSize; // Sparse access
            testBuffer[idx] += k;
        }
        const mEnd = performance.now();
        ramDna.push(Math.round((mEnd - mStart) * 10000)); // Arbitrary high-res scale
    }
    
    self.postMessage({ type: 'results', results, ramDna });
  }
};
