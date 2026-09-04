// src/services/noiseBridge.ts
// Bridge between the background probe worker and the main application logic

let latestNoise: number[] = [];

export function updateNoise(deltas: number[]) {
  latestNoise = deltas;
}

export function getCpuNoise(): number[] {
  // Fallback to a small simulated jitter if no worker data yet
  if (latestNoise.length === 0) {
    return Array.from({ length: 16 }, () => Math.random() * 2);
  }
  return latestNoise;
}
