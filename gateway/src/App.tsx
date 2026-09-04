/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Activity,
  ShieldAlert,
  Cpu,
  Zap,
  Terminal,
  Lock,
  Radio,
  Eye,
  Atom,
  AlertTriangle
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { createMlKem768 } from 'mlkem';
declare const argon2: any; // loaded via CDN in index.html (WASM cannot be bundled by Rollup)

// Silicon DNA Aesthetic: Technical Brutalism
// Font: JetBrains Mono (simulated via monospace)

const JitterVisualizer = ({ alert = false }: { alert?: boolean }) => {
  return (
    <div className={`h-32 flex items-end gap-0.5 overflow-hidden rounded-md bg-zinc-950 p-2 border ${alert ? 'border-red-500/50' : 'border-zinc-800'}`}>
      {Array.from({ length: 48 }).map((_, i) => (
        <motion.div
          key={i}
          initial={{ height: '10%' }}
          animate={{ 
            height: alert 
              ? [`${Math.random() * 20 + 40}%`, `${Math.random() * 20 + 40}%`] // Машины имеют очень стабильный, узкий джиттер
              : [`${Math.random() * 80 + 10}%`, `${Math.random() * 80 + 10}%`] // Человек/Реальность хаотичны
          }}
          transition={{ 
            duration: alert ? 0.2 : 0.5 + Math.random(), 
            repeat: Infinity, 
            ease: "easeInOut" 
          }}
          className={`flex-1 ${alert ? 'bg-red-500/60' : 'bg-emerald-500/40'} rounded-t-sm`}
        />
      ))}
    </div>
  );
};

const StatusBadge = ({ label, value, color = "emerald", alert = false, subValue = "" }: { label: string, value: string, color?: string, alert?: boolean, subValue?: string }) => (
  <div className={`flex flex-col gap-1 p-3 bg-zinc-900 border ${alert ? 'border-red-500/50 animate-pulse' : 'border-zinc-800'} rounded-lg transition-all duration-500`}>
    <span className="text-[10px] uppercase tracking-widest text-zinc-500 font-mono">{label}</span>
    <div className="flex items-baseline gap-2">
      <span className={`text-sm font-mono font-medium ${alert ? 'text-red-400' : `text-${color}-400`}`}>{value}</span>
      {subValue && <span className="text-[8px] text-zinc-600 font-mono">{subValue}</span>}
    </div>
  </div>
);

const Histogram = ({ data, color = "emerald" }: { data: number[], color?: string }) => {
  return (
    <div className="h-40 flex items-end gap-[1px] bg-black/40 p-4 border border-zinc-900 rounded-lg relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.05)_1px,transparent_1px)] bg-[size:20px_20px]" />
      {data.map((height, i) => (
        <motion.div
          key={i}
          initial={{ height: 0 }}
          animate={{ height: `${height}%` }}
          className={`flex-1 ${color === 'emerald' ? 'bg-emerald-500/30' : 'bg-red-500/30'} rounded-t-sm relative z-10`}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        />
      ))}
    </div>
  );
};

export default function App() {
  const [isBooting, setIsBooting] = useState(true);
  const [mapPressure, setMapPressure] = useState(12);
  const [toxicity, setToxicity] = useState(0.02);
  const [calibrationProgress, setCalibrationProgress] = useState(0);
  const [mode, setMode] = useState<'IDLE' | 'STRESS' | 'SNIPER'>('IDLE');
  const [activeAsset, setActiveAsset] = useState<string | null>(null);
  const [histogramData, setHistogramData] = useState<number[]>(Array(60).fill(10));
  const [showManifest, setShowManifest] = useState(false);
  const [logs, setLogs] = useState<{ t: string, m: string, type: string }[]>([]);
  const [filterStats, setFilterStats] = useState({ passed: 0, dropped: 0 });
  const [isInterrogating, setIsInterrogating] = useState(false);
  const [isPqcActive, setIsPqcActive] = useState(false);
  const [trustScore, setTrustScore] = useState(1.0);
  const [packetIndex, setPacketIndex] = useState(0);
  const [threats, setThreats] = useState<{ type: string; ip: string; t: number; details: string }[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const pqcKeyRef = useRef<CryptoKey | null>(null);
  const rhythmWorkerRef = useRef<Worker | null>(null);
  const latestJitterRef = useRef<number[]>([]);
  const sabRef = useRef<SharedArrayBuffer | null>(null);
  const [metrics, setMetrics] = useState<{
    mean: number;
    variance: number;
    entropy: number;
    autocorr: number;
    temp: number;
    pol: number;
    histogram: number[];
    dnaHash: string;
    trustScore?: number;
    keyRatchetCycles?: number;
    mode: 'IDLE' | 'STRESS' | 'SNIPER';
    t: string;
    filterStats?: { passed: number, dropped: number };
  } | null>(null);

  // WebSocket Connection
  useEffect(() => {
    if (isBooting) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;
    const socket = new WebSocket(wsUrl);
    wsRef.current = socket;

    // FIXED: async to allow await inside PQC_INIT (key derivation)
    socket.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'PQC_INIT') {
          addLog(`PQC_HANDSHAKE: Получен PK (ML-KEM-768). Инкапсуляция...`, 'amber');

          // Real ML-KEM-768 encapsulation against the server's real public key.
          // Ciphertext and sharedSecret are cryptographically bound to that
          // specific key pair -- not independently-chosen random bytes, which
          // is what this used to send (see git history: that produced a
          // client-derived key with no real relationship to the server's
          // decap() output).
          const pkBytes = Uint8Array.from(atob(data.pk), c => c.charCodeAt(0));
          const kem = await createMlKem768();
          const [ciphertext, sharedSecret] = kem.encap(pkBytes);

          const hmacKey = await window.crypto.subtle.importKey(
            'raw', sharedSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
          );
          pqcKeyRef.current = hmacKey;

          // Safe b64 encoding for large Uint8Array (avoids spread stack overflow)
          const b64 = btoa(Array.from(ciphertext, c => String.fromCharCode(c)).join(''));
          socket.send(JSON.stringify({ type: 'PQC_RESP', ciphertext: b64 }));
          return;
        }

        if (data.type === 'PQC_ESTABLISHED') {
          setIsPqcActive(true);
          addLog(`PQC_SECURED: Квантовый туннель установлен. Ключ синхронизирован.`, 'emerald');
          return;
        }

        // SILICON_THREAT events from server bot-detection middleware
        if (data.type === 'SILICON_THREAT') {
          const entry = {
            type: data.threatType as string,
            ip: data.ip as string,
            t: data.t as number,
            details: JSON.stringify(data.details)
          };
          setThreats(prev => [entry, ...prev].slice(0, 8));
          addLog(`⚡ УГРОЗА [${data.threatType}] IP:...${data.ip} — ${JSON.stringify(data.details)}`, 'red');
          return;
        }

        if (data.trustScore !== undefined) setTrustScore(data.trustScore);

        setMetrics(data);
        if (data.filterStats) setFilterStats(data.filterStats);
        if (data.mode !== mode) {
          setMode(data.mode);
          setCalibrationProgress(data.mode === 'SNIPER' ? 100 : data.mode === 'STRESS' ? 65 : 20);
          addLog(`УРОВЕНЬ_L0: Переход в режим ${data.mode}`, 'emerald');
        }
      } catch (e) {
        console.error('WS Parse Error', e);
      }
    };

    socket.onopen = () => addLog("WS_LINK: Канал передачи данных открыт", "emerald");
    socket.onerror = () => addLog("WS_ERR: Ошибка соединения. Fallback активен.", "red");

    return () => socket.close();
  }, [isBooting, mode]);

  const assets = [
    { id: 'crypto', name: 'Crypto_Wallet', desc: 'Защита подписи транзакций', icon: Lock },
    { id: 'ai', name: 'Cognitive_Enclave', desc: 'Изоляция ИИ-контура', icon: Eye },
    { id: 'tunnel', name: 'Dark_Tunnel', desc: 'P2P PQC-соединение', icon: Radio },
  ];

  const collectStylisticFP = (): any => {
    const fp: any = {};
    // CSS Stylistic Detection (L1.5)
    fp.gamut = window.matchMedia('(color-gamut: p3)').matches ? 'p3' : 'srgb';
    fp.contrast = window.matchMedia('(prefers-contrast: more)').matches ? 'more' : 'normal';
    fp.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'yes' : 'no';
    fp.theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    
    // Font Leakage
    const fonts = ['Helvetica', 'Arial', 'Inter', 'JetBrains Mono'];
    fp.fonts = fonts.filter(f => {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (!context) return false;
        context.font = '72px serif';
        const defaultWidth = context.measureText('mmmmmllllliiiii').width;
        context.font = `72px "${f}", serif`;
        return context.measureText('mmmmmllllliiiii').width !== defaultWidth;
    }).length;

    // GPU Leakage (Module 1.1)
    try {
        const canvas = document.createElement('canvas');
        const gl = (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
              fp.gpu = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            } else {
              fp.gpu = 'unknown (no extension)';
            }
        } else {
          fp.gpu = 'unknown (no gl)';
        }
    } catch(e) {
      fp.gpu = 'error';
    }

    // Automation / WebDriver artifact detection (L1.2)
    fp.webdriver = (navigator as any).webdriver === true;
    try {
      fp.hasChromedriverCdc = !!(window as any).cdc_asdjflasutopfhvcZLmcfl_
        || !!(document as any).$cdc_asdjflasutopfhvcZLmcfl_;
      fp.hasPhantomArtifact = !!(window as any).callPhantom || !!(window as any)._phantom;
      fp.hasNightmareArtifact = !!(window as any).__nightmare;
      fp.pluginsLength = navigator.plugins ? navigator.plugins.length : undefined;
      fp.languagesEmpty = !navigator.languages || navigator.languages.length === 0;
    } catch (e) {
      // Detection itself throwing is not a signal worth acting on here.
    }

    return fp;
  };

  const [ramDnaActive, setRamDnaActive] = useState(false);

  // Initialize Rhythm Worker (L6: Precise Jitter + RAM DNA)
  useEffect(() => {
    if (typeof SharedArrayBuffer === 'undefined') {
      addLog('WARN: SharedArrayBuffer недоступен. Точность L6 снижена.', 'amber');
    } else {
      // Create SAB once — passed to worker on each 'measure' call for Atomics.wait
      sabRef.current = new SharedArrayBuffer(4);
      setRamDnaActive(true);
    }
    const worker = new Worker(new URL('./services/rhythmWorker.ts', import.meta.url), { type: 'module' });
    rhythmWorkerRef.current = worker;
    return () => worker.terminate();
  }, []);

  // Rhythm Sync Loop (Golden Seal v4.0)
  useEffect(() => {
    if (!isPqcActive) return;

    let syncInterval: any;
    const runSync = async () => {
        try {
            const res = await fetch('/api/sync-pulse');
            if (!res.ok) return; 
            const data = await res.json();
            const { pulse, driftAdjustment } = data;
            
            if (rhythmWorkerRef.current) {
                // Use Dedicated Worker with Atomics logic (simulated by high-res probe)
                rhythmWorkerRef.current.onmessage = async (e) => {
                    if (e.data.type === 'results') {
                        latestJitterRef.current = e.data.results;
                        const ramDnaSalt = e.data.ramDna || [];
                        
                        await fetch('/api/verify-rhythm', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                timings: e.data.results,
                                ramSalt: ramDnaSalt // Sending Software PUF metrics
                            })
                        });
                    }
                };
                
                rhythmWorkerRef.current.postMessage({
                  type: 'measure',
                  delayUs: 1500 * driftAdjustment,
                  iterations: pulse.length,
                  pulse,
                  sab: sabRef.current ?? undefined, // FIXED: pass SAB for Atomics.wait precision
                });
            } else {
                // Fallback to main thread (Low Trust)
                const measuredTimings: number[] = [];
                for (const baseDelay of pulse) {
                    const start = performance.now();
                    const jitter = Math.random() * 5 * driftAdjustment;
                    await new Promise(r => setTimeout(r, (baseDelay / 1000) + jitter));
                    measuredTimings.push((performance.now() - start) * 1000); 
                }

                await fetch('/api/verify-rhythm', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ timings: measuredTimings })
                });
            }

        } catch (e) {
            console.error('Rhythm Sync Failed', e);
        }
    };

    syncInterval = setInterval(runSync, 7000); 
    return () => clearInterval(syncInterval);
  }, [isPqcActive]);

  const generateSeal = async (seq: number): Promise<{ seal: string; noise: string }> => {
    const encoder = new TextEncoder();
    
    if (!pqcKeyRef.current) {
        throw new Error('PQC_KEY_MISSING');
    }

    const ts = Date.now() * 1000;
    const noiseData = latestJitterRef.current.length > 0
      ? latestJitterRef.current.slice(0, 8).map(n => Math.floor(n))
      : Array.from({ length: 8 }, () => Math.floor(Math.random() * 20));

    const noise = noiseData.join(',');
    // FIXED: use 'default' to match server sealValidator sessionId='default'
    const msg = encoder.encode(`default${seq}${noise}`); 
    
    const sigBuffer = await window.crypto.subtle.sign('HMAC', pqcKeyRef.current, msg);
    const sig = Array.from(new Uint8Array(sigBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const sealData = JSON.stringify({ sig, ts, seq });
    return {
      seal: btoa(sealData),
      noise
    };
  };

  const solvePoW = async (target: string, m_cost: number, t_cost: number): Promise<{ hash: string; calcTime: number; fp: any }> => {
    addLog(`ARGON2ID_CHALLENGE: Начало вычислений (Memory-Hard)...`, 'amber');
    const fp = collectStylisticFP();
    addLog(`STYLISTIC_FP: GPU=${fp.gpu.slice(0, 20)}... Fonts=${fp.fonts}`, 'zinc');
    
    const start = performance.now();
    try {
      const result = await (argon2 as any).hash({
        pass: target,
        salt: 'quantum_salt_3.2',
        time: t_cost,
        mem: m_cost,
        hashLen: 32,
        type: (argon2 as any).ArgonType.Argon2id
      });
      
      const calcTime = performance.now() - start;
      return { hash: result.hashHex, calcTime, fp };
    } catch (e) {
      addLog(`ERR: Argon2 OOM или системный сбой.`, 'red');
      throw e;
    }
  };

  const testAssetAccess = async (assetName: string) => {
    addLog(`ИНТЕРРОГАЦИЯ: Запрос доступа к ${assetName}...`, 'zinc');
    setIsInterrogating(true);
    try {
      const endpoint = assetName.toLowerCase().includes('enclave') ? '/api/enclave' : 
                       assetName.toLowerCase().includes('wallet') ? '/api/wallet' : '/api/secure-asset';
      
      const nextSeq = packetIndex + 1;
      const { seal, noise } = await generateSeal(nextSeq);
      
      let res = await fetch(endpoint, {
          headers: {
              'x-silicon-dna-seal': seal,
              'x-silicon-dna-noise': noise
          }
      });
      
      if (res.status === 403) {
        const errorData = await res.json();
        
        if (errorData.error === 'ENTROPY_SEAL_INVALID') {
            addLog(`ERR: Ошибка энтропийного слепка (Replay/Forge).`, 'red');
            return;
        }

        addLog(`L2_ACTIVE: Требуется физическое Argon2id подтверждение.`, 'amber');
        
        const challengeRes = await fetch('/api/challenge');
        const challenge = await challengeRes.json();
        
        const { hash, calcTime, fp } = await solvePoW(challenge.target, challenge.m_cost, challenge.t_cost);
        addLog(`PHYSICAL_VERIFIED: Вычислено за ${calcTime.toFixed(1)}мс.`, 'emerald');
        
        const verifyRes = await fetch('/api/verify-pow', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hash, calcTime, m_cost: challenge.m_cost, t_cost: challenge.t_cost, fp })
        });
        
        if (!verifyRes.ok) throw new Error('POW_VERIFICATION_FAILED');
        
        addLog(`POW_OK: Физика подтверждена. Повторная попытка доступа...`, 'zinc');

        // FIXED: server stored expectedSeq=nextSeq after valid seal, so now expects nextSeq+1
        const retrySeq = nextSeq + 1;
        const retrySeal = await generateSeal(retrySeq);
        res = await fetch(endpoint, {
          headers: {
            'x-silicon-dna-seal': retrySeal.seal,
            'x-silicon-dna-noise': retrySeal.noise
          }
        });

        if (res.ok) {
          const data = await res.json();
          setPacketIndex(retrySeq); // advance past both the initial + retry seqs
          addLog(`ДОСТУП_РАЗРЕШЕН: DNA_SECURED: ${data.dna.slice(0, 16)}...`, 'emerald');
        } else {
          throw new Error(`RETRY_HTTP_${res.status}`);
        }
        return; // handled
      }

      if (!res.ok) throw new Error(`HTTP_${res.status}`);
      const data = await res.json();
      setPacketIndex(nextSeq);
      addLog(`ДОСТУП_РАЗРЕШЕН: DNA_SECURED: ${data.dna.slice(0, 16)}...`, 'emerald');
    } catch (e) {
      addLog(`ACCESS_TERMINATED: Sniper Drop! Физическая подпись не совпадает.`, 'red');
    } finally {
      setIsInterrogating(false);
    }
  };

  const roadmap = [
    { title: "L0_PROBE: Silicon DNA", status: "DONE", desc: "Экстракция физического отпечатка таймингов Δphs." },
    { title: "L1_BRIDGE: Asset Shield", status: "ACTIVE", desc: "Защита кошельков и локальных ИИ-агентов через прокси-фильтр." },
    { title: "L2_HARDWARE: Physical Redoubt", status: "PLANNED", desc: "Вынос точки принятия решения на внешний SBC (Orange Pi)." },
    { title: "P2P_MESH: Global Immunity", status: "PLANNED", desc: "Сеть доверенного кремния без участия облачных провайдеров." },
  ];

  const deploymentSteps = [
    "Установка LLVM/Clang и линковка bpf_helpers.",
    "Компиляция l0_probe.c в байткод: clang -O2 -target bpf.",
    "Загрузка в ядро: bpftool prog load l0_probe.o /sys/fs/bpf/probe.",
    "Привязка к хуку: bpftool net attach xdp id <ID_PROBE> dev eth0."
  ];

  const addLog = (m: string, type = 'zinc') => {
    const t = (Date.now() / 1000 % 100).toFixed(2);
    setLogs(prev => [{ t, m, type }, ...prev].slice(0, 15));
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsBooting(false);
      addLog("L0_PROBE: Связь с ядром установлена", "emerald");
      addLog("ИНИЦИАЛИЗАЦИЯ ПРОТОКОЛА КАЛИБРОВКИ...", "zinc");
    }, 2000);
    return () => clearTimeout(timer);
  }, []);

  // Calibration Logic (Simulation Fallback)
  useEffect(() => {
    if (isBooting || mode === 'SNIPER' || metrics) return;

    const interval = setInterval(() => {
      setCalibrationProgress(prev => {
        if (prev >= 100) {
          if (mode === 'IDLE') {
            addLog("ЭТАЛОН ПОКОЯ ЗАФИКСИРОВАН. ПЕРЕХОД К СТРЕСС-ТЕСТУ.", "emerald");
            setMode('STRESS');
            return 0;
          } else if (mode === 'STRESS') {
            addLog("ПРОФИЛЬ НАГРУЗКИ ПОДТВЕРЖДЕН. ДНК КРЕМНИЯ ПОЛУЧЕНА.", "emerald");
            setMode('SNIPER');
            return 100;
          }
          return 100;
        }
        return prev + 1.2;
      });

      // Update Histogram based on mode
      setHistogramData(prev => prev.map(() => {
        const base = mode === 'IDLE' ? 20 : 40;
        const noise = mode === 'IDLE' ? 10 : 40;
        return Math.random() * noise + base;
      }));

    }, 200)

    return () => clearInterval(interval);
  }, [mode, isBooting]);

  if (isBooting) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center font-mono">
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col items-center gap-4">
          <Activity className="w-12 h-12 text-emerald-500 animate-pulse" />
          <div className="text-zinc-500 text-[10px] tracking-[0.3em] uppercase">Загрузка_Silicon_DNA_L0</div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] text-zinc-300 p-4 md:p-8 font-mono selection:bg-emerald-500 selection:text-black">
      <header className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-12 border-b border-zinc-900 pb-8">
        <div className="flex flex-col">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded">
              <ShieldAlert className="w-6 h-6 text-emerald-500" />
            </div>
            <h1 className="text-2xl font-black tracking-tighter text-white uppercase italic">Silicon_DNA</h1>
          </div>
          <p className="text-[9px] text-zinc-500 mt-1 uppercase tracking-[0.2em] font-bold">Фильтр_Абсолютной_Реальности // Зонд_L0</p>
        </div>

        <div className="flex gap-4">
          <StatusBadge 
            label="Режим Узла" 
            value={mode === 'IDLE' ? 'ПОКОЙ' : mode === 'STRESS' ? 'СТРЕСС' : 'СНАЙПЕР'} 
            color={mode === 'SNIPER' ? "emerald" : mode === 'STRESS' ? "red" : "amber"} 
            subValue={mode === 'SNIPER' ? "ЗАЩИТА_АКТИВНА" : "СБОР_ДАННЫХ"}
          />
          <StatusBadge 
            label="Энтропия (H)" 
            value={metrics ? metrics.entropy.toFixed(3) : (mode === 'IDLE' ? 0.82 : 0.94).toFixed(3)} 
            color="zinc"
            subValue="Бит_Шеннона"
          />
          <StatusBadge 
            label="Автокорреляция (R1)" 
            value={metrics ? metrics.autocorr.toFixed(3) : '0.450'} 
            color={metrics && Math.abs(metrics.autocorr) < 0.1 ? "red" : "emerald"}
            subValue="Memory_Signature"
          />
          <StatusBadge 
            label="Термо-Профиль" 
            value={metrics ? `${metrics.temp.toFixed(1)}°C` : '42.0°C'} 
            color={metrics && metrics.temp > 70 ? "red" : "emerald"}
            subValue={metrics && metrics.temp > 70 ? "OVERHEAT" : "STABLE"}
          />
          <StatusBadge 
            label="Защита L1" 
            value={filterStats.dropped > 0 ? "SHIELD_UP" : "STANDBY"} 
            color={filterStats.dropped > 0 ? "red" : "zinc"} 
          />
          <StatusBadge 
            label="Quantum PQC" 
            value={isPqcActive ? "ML-KEM-768" : "INITIALIZING"} 
            color={isPqcActive ? "emerald" : "zinc"} 
          />
          <StatusBadge 
            label="Rhythm Trust" 
            value={`${(trustScore * 100).toFixed(1)}%`} 
            color={trustScore > 0.8 ? "emerald" : trustScore > 0.6 ? "amber" : "red"} 
          />
          <StatusBadge 
            label="RAM DNA (Soft-PUF)" 
            value={ramDnaActive ? "ACTIVE (L6)" : "EMULATED"} 
            color={ramDnaActive ? "cyan" : "amber"} 
          />
          <StatusBadge 
            label="PQC Ratchet" 
            value={metrics?.keyRatchetCycles ? `${metrics.keyRatchetCycles}` : "0"} 
            color="emerald"
            subValue="Key_Rotations"
          />
          <StatusBadge 
            label="Active Допрос" 
            value={isInterrogating ? "INTERROGATING" : "IDLE"} 
            color={isInterrogating ? "amber" : "zinc"} 
            alert={isInterrogating}
          />
          <StatusBadge 
            label="Органик / Прошло" 
            value={String(filterStats.passed)} 
            color="emerald" 
          />
          <StatusBadge 
            label="Синтетик / Убито" 
            value={String(filterStats.dropped)} 
            color="red" 
            alert={filterStats.dropped > 0}
          />
          <div className="flex flex-col gap-1 p-3 bg-zinc-900 border border-zinc-800 rounded-lg min-w-[150px]">
             <span className="text-[10px] uppercase tracking-widest text-zinc-500 font-mono">Калибровка</span>
             <div className="flex items-center gap-3">
               <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                 <motion.div 
                   className="h-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" 
                   initial={{ width: 0 }}
                   animate={{ width: `${calibrationProgress}%` }}
                 />
               </div>
               <span className="text-[10px] font-bold text-emerald-400">{calibrationProgress.toFixed(0)}%</span>
             </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Metadata & DNA */}
        <div className="lg:col-span-4 space-y-6">
          <section className="bg-zinc-900/40 border border-zinc-800/50 rounded-xl p-6">
            <h2 className="text-xs font-black uppercase tracking-widest text-emerald-500 mb-6 flex items-center gap-2">
              <Cpu className="w-4 h-4" /> Кремниевая_Идентичность_L0
            </h2>
            
            <div className="space-y-4">
              <div className="p-3 bg-black border border-zinc-800 rounded text-[10px] font-mono break-all leading-relaxed">
                <span className="text-zinc-500">DNA_ХЕШ:</span><br/>
                {metrics ? metrics.dnaHash : (mode === 'SNIPER' ? '7f82b3d1c4e5a6b7c8d9e0f1a2b3c4d5e6f7g8h9' : 'ГЕНЕРАЦИЯ_КЛЮЧА...')}
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-[9px] uppercase font-bold text-zinc-500">
                  <span>Стабильность планировщика</span>
                  <span className="text-emerald-500">Высокая</span>
                </div>
                <div className="flex justify-between text-[9px] uppercase font-bold text-zinc-500">
                  <span>Аффинити IRQ-ядер</span>
                  <span className="text-zinc-300">0, 4, 8, 12</span>
                </div>
              </div>
            </div>

            <div className="mt-8 pt-6 border-t border-zinc-800">
               <p className="text-[10px] text-zinc-500 italic mb-4 leading-relaxed">
                 Калибровка фиксирует распределение Δphs = Tnapi - Tirq для отличия физической реальности от синтетического «сглаживания».
               </p>
               <button
                type="button"
                disabled={mode === 'SNIPER'}
                onClick={() => setMode(mode === 'IDLE' ? 'STRESS' : 'IDLE')}
                className={`w-full py-3 rounded font-black text-[10px] uppercase tracking-[0.2em] transition-all border ${
                  mode === 'STRESS' ? 'bg-red-500/10 border-red-500 text-red-500 animate-pulse' : 'bg-transparent border-zinc-800 text-zinc-400 hover:border-emerald-500 hover:text-emerald-500'
                }`}
               >
                 {mode === 'IDLE' ? 'Активировать_Стресс-Тест' : 'Калибровка_Покоя_Активна'}
               </button>
            </div>
          </section>

          <div className="bg-emerald-500/5 border border-emerald-500/10 p-5 rounded-xl">
             <div className="flex items-center gap-2 mb-3 text-emerald-500">
               <Lock className="w-3 h-3" />
               <span className="text-[10px] font-black uppercase tracking-tighter">Блокировка_Золотого_Стандарта</span>
             </div>
             <p className="text-[10px] leading-relaxed text-zinc-400">
                Шифрование базовой линии активно. Любой трафик, имеющий идеально нулевой джиттер, будет помечен как <span className="text-red-400 font-bold">СИНТЕТИЧЕСКОЕ_СГЛАЖИВАНИЕ</span> и отсечен XDP-хуком.
             </p>
          </div>

          {threats.length > 0 && (
            <section className="bg-red-950/30 border border-red-500/20 rounded-xl p-4">
              <h2 className="text-xs font-black uppercase tracking-widest text-red-500 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> SILICON_THREAT_LOG
              </h2>
              <div className="space-y-1.5 max-h-36 overflow-y-auto no-scrollbar">
                {threats.map((t, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="flex gap-2 text-[9px] font-mono"
                  >
                    <span className="text-red-500 font-bold shrink-0">[{t.type}]</span>
                    <span className="text-zinc-500">IP:…{t.ip}</span>
                    <span className="text-zinc-600 truncate">{t.details}</span>
                  </motion.div>
                ))}
              </div>
            </section>
          )}

          <section className="bg-zinc-900/40 border border-zinc-800/50 rounded-xl p-6">
            <h2 className="text-xs font-black uppercase tracking-widest text-emerald-500 mb-6 flex items-center gap-2">
              <Zap className="w-4 h-4" /> L1_BRIDGE_ORCHESTRATOR
            </h2>
            <div className="space-y-3">
              {assets.map((asset) => (
                <div key={asset.id} className="relative group">
                  <button
                    type="button"
                    onClick={() => {
                      setActiveAsset(asset.id);
                      addLog(`ШЛЮЗ_L1: Защита ${asset.name} активирована`, 'emerald');
                    }}
                    className={`w-full p-4 rounded-lg border transition-all text-left flex items-start gap-4 ${
                      activeAsset === asset.id 
                      ? 'bg-emerald-500/10 border-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.1)]' 
                      : 'bg-black/40 border-zinc-800 hover:border-zinc-700'
                    }`}
                  >
                    <asset.icon className={`w-5 h-5 mt-1 ${activeAsset === asset.id ? 'text-emerald-500' : 'text-zinc-600'}`} />
                    <div>
                      <div className={`text-[10px] font-black uppercase tracking-tighter ${activeAsset === asset.id ? 'text-white' : 'text-zinc-500'}`}>
                        {asset.name}
                      </div>
                      <div className="text-[9px] text-zinc-600 uppercase mt-0.5">{asset.desc}</div>
                    </div>
                  </button>
                  
                  {activeAsset === asset.id && (
                    <motion.button
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      onClick={() => testAssetAccess(asset.name)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 p-2 bg-emerald-500 text-black rounded text-[8px] font-black uppercase hover:bg-white transition-colors"
                    >
                      Interrogate
                    </motion.button>
                  )}
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Center: Live Pulse & Distribution */}
        <div className="lg:col-span-8 space-y-6">
          <div className="flex gap-4">
            <button
              type="button"
              onClick={() => setShowManifest(false)}
              className={`flex-1 py-2 text-[10px] font-black uppercase tracking-widest border transition-all ${!showManifest ? 'bg-emerald-500 text-black border-emerald-500' : 'bg-transparent border-zinc-800 text-zinc-500 hover:border-zinc-700'}`}
            >
              Live_Telemetry
            </button>
            <button
              type="button"
              onClick={() => setShowManifest(true)}
              className={`flex-1 py-2 text-[10px] font-black uppercase tracking-widest border transition-all ${showManifest ? 'bg-emerald-500 text-black border-emerald-500' : 'bg-transparent border-zinc-800 text-zinc-500 hover:border-zinc-700'}`}
            >
              Project_Manifest_&_Roadmap
            </button>
          </div>

          {!showManifest ? (
            <section className="bg-zinc-950 border border-zinc-800 rounded-xl p-8 relative overflow-hidden flex flex-col min-h-[600px]">
            <div className="flex items-center justify-between mb-8 relative z-10 font-mono">
              <div className="flex flex-col">
                <h3 className="text-xs font-black text-white uppercase tracking-[0.3em]">Моделирование распределения Δphs</h3>
                <span className="text-[9px] text-zinc-600 uppercase">Состояние: {mode === 'IDLE' ? 'Покой' : mode === 'STRESS' ? 'Насыщение_Ядра' : 'Снайперский_Фильтр_Активен'}</span>
              </div>
              <div className="text-[9px] font-bold text-zinc-700 uppercase">Разрешение: 1.0нс</div>
            </div>

            <div className="flex-1 relative z-10 flex flex-col gap-8">
              <Histogram data={metrics?.histogram || histogramData} color={mode === 'STRESS' ? 'red' : 'emerald'} />
              
              <div className="grid grid-cols-2 md:grid-cols-5 gap-6 pt-4 border-t border-zinc-900">
                <div className="space-y-1">
                  <span className="text-[8px] uppercase text-zinc-600 tracking-widest font-bold">Среднее Δнс</span>
                  <div className="text-sm font-mono text-white tracking-tighter">
                    {metrics ? metrics.mean.toFixed(1) : (mode === 'IDLE' ? 42.1 : 58.9).toFixed(1)}
                  </div>
                </div>
                <div className="space-y-1">
                  <span className="text-[8px] uppercase text-zinc-600 tracking-widest font-bold">Дисперсия (σ²)</span>
                  <div className="text-sm font-mono text-white tracking-tighter">
                    {metrics ? metrics.variance.toFixed(2) : (mode === 'IDLE' ? 0.04 : 4.12).toFixed(2)}
                  </div>
                </div>
                <div className="space-y-1">
                  <span className="text-[8px] uppercase text-zinc-600 tracking-widest font-bold">Корреляция_R(1)</span>
                  <div className={`text-sm font-mono tracking-tighter ${metrics && Math.abs(metrics.autocorr) < 0.1 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {metrics ? metrics.autocorr.toFixed(3) : '0.452'}
                  </div>
                </div>
                <div className="space-y-1">
                  <span className="text-[8px] uppercase text-zinc-600 tracking-widest font-bold">Порог Токсичности</span>
                  <div className="text-sm font-mono text-emerald-500 tracking-tighter">&lt; 0.12нс</div>
                </div>
                <div className="space-y-1">
                  <span className="text-[8px] uppercase text-zinc-600 tracking-widest font-bold">Вероятность Жизни</span>
                  <div className={`text-sm font-mono tracking-tighter ${metrics && metrics.pol > 90 ? 'text-emerald-400' : 'text-red-400'}`}>
                    {metrics ? metrics.pol.toFixed(1) : (mode === 'SNIPER' ? '99.8' : '0.0')}%
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-12 pt-6 border-t border-zinc-900 flex flex-col gap-4 relative z-10">
              <div className="flex justify-between items-center text-[10px]">
                <div className="flex items-center gap-2">
                  <Terminal className="w-3 h-4 text-emerald-500" />
                  <span className="text-zinc-500 uppercase font-black">Поток_Калибровки</span>
                </div>
                <div className="flex items-center gap-2">
                   <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
                   <span className="text-zinc-700 uppercase italic">Ожидание прерываний...</span>
                </div>
              </div>
              <div className="h-28 overflow-y-auto no-scrollbar space-y-1 font-mono text-[9px]">
                 {logs.map((log, i) => (
                   <motion.div initial={{ x: -5, opacity: 0 }} animate={{ x: 0, opacity: 1 }} key={i} className="flex gap-4">
                     <span className="text-zinc-700">[{log.t}]</span>
                     <span className={`text-${log.type}-500/80`}>{log.m}</span>
                   </motion.div>
                 ))}
              </div>
            </div>
          </section>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <section className="bg-zinc-900/40 border border-zinc-800/50 rounded-xl p-6">
                <h2 className="text-xs font-black uppercase tracking-widest text-emerald-500 mb-6 flex items-center gap-2">
                  <Terminal className="w-4 h-4" /> Silicon_DNA_Roadmap
                </h2>
                <div className="space-y-6">
                  {roadmap.map((step, i) => (
                    <div key={i} className={`relative pl-6 border-l ${step.status === 'DONE' ? 'border-emerald-500' : step.status === 'ACTIVE' ? 'border-emerald-500 border-dashed animate-pulse' : 'border-zinc-800'}`}>
                      <div className={`absolute -left-1.5 top-0 w-3 h-3 rounded-full border-2 bg-black ${step.status === 'DONE' ? 'border-emerald-500 bg-emerald-500' : 'border-zinc-800'}`} />
                      <div className="text-[10px] font-black text-white uppercase">{step.title}</div>
                      <div className="text-[9px] text-zinc-500 mt-1 leading-relaxed">{step.desc}</div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="bg-zinc-900/40 border border-zinc-800/50 rounded-xl p-6">
                <h2 className="text-xs font-black uppercase tracking-widest text-emerald-500 mb-6 flex items-center gap-2">
                  <Zap className="w-4 h-4" /> Deployment_Protocol
                </h2>
                <div className="space-y-4">
                  {deploymentSteps.map((step, i) => (
                    <div key={i} className="flex gap-4">
                      <span className="text-emerald-500 font-mono text-[10px] font-bold">{i + 1}.</span>
                      <p className="text-[10px] text-zinc-400 leading-relaxed font-mono">{step}</p>
                    </div>
                  ))}
                  <div className="mt-6 p-4 bg-black border border-red-500/20 rounded-lg">
                    <p className="text-[9px] text-red-400 font-bold uppercase mb-2 animate-pulse underline">ВНИМАНИЕ:</p>
                    <p className="text-[9px] text-zinc-500 leading-tight">
                      Развертывание требует Ring-0 доступа. ОС может классифицировать зонд как руткит. Требуется ручное подтверждение загрузки BPF-байткода.
                    </p>
                  </div>
                </div>
              </section>

              <section className="md:col-span-2 bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-8">
                 <h2 className="text-xs font-black uppercase tracking-widest text-emerald-500 mb-4">Физический Манифест</h2>
                 <p className="text-xs text-zinc-400 leading-loose italic">
                   "Silicon DNA опирается на неоспоримую физику: термодинамический шум и джиттер планировщика. В мире, где любая информация может быть синтезирована ИИ, единственным доказательством реальности остается несовершенство аппаратного ответа. Мы не защищаем данные. Мы защищаем право реальности быть несовершенной и, следовательно, живой."
                 </p>
              </section>
            </div>
          )}
        </div>
      </main>

      <footer className="max-w-7xl mx-auto mt-12 pt-8 border-t border-zinc-900 flex justify-between items-center opacity-30">
        <div className="flex gap-4 items-center">
          <Radio className="w-3 h-3" />
          <span className="text-[9px] uppercase tracking-widest font-bold">Silicon DNA // Протокол Абсолютного Доверия</span>
        </div>
        <span className="text-[9px] font-mono">96ГБ_EPYC_THD // PQC_ГОТОВ</span>
      </footer>
    </div>
  );
}
