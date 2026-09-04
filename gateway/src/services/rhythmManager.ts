// src/services/rhythmManager.ts
// Протокол "Golden Seal" v4.0 — Динамический Аккорд
// Управляет микро-ритмической подписью и калибровкой дрейфа

import crypto from 'crypto';

// Конфигурация ритма
const PI_SEQUENCE = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3];
const BASE_DELAY_US = 150; // базовый интервал в микросекундах
const DRIFT_WINDOW = 0.15; // 15% допуск на плавание частоты процессора
const TRUST_DECAY_RATE = 0.05; // скорость падения доверия при отсутствии подтверждений

// Хранилище активных ритмических сессий
const rhythmSessions = new Map<string, RhythmState>();

interface RhythmState {
  sessionId: string;
  secretSequence: number[]; // R — базовый ритм сервера
  clientNoiseProfile: number[]; // накопленный шум клиента
  trustScore: number; // 0.0 - 1.0
  lastSync: number; // timestamp последней успешной сверки
  driftCompensation: number; // текущий коэффициент коррекции
}

/**
 * Генерирует уникальную ритмическую последовательность для новой сессии.
 * Основана на π-числах, перемешанных ключом PQC-сессии.
 */
export function generateSyncPulse(sessionId: string, pqcSharedSecret: Buffer): number[] {
  const seed = crypto.createHmac('sha256', pqcSharedSecret).update(sessionId).digest();
  const shuffled = [...PI_SEQUENCE];
  
  // Fisher-Yates shuffle с криптографическим seed
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = seed[i % seed.length] % (i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  
  // Преобразуем в микросекундные дельты
  const pulse = shuffled.map(n => n * BASE_DELAY_US + (seed[n % seed.length] % 50));
  
  // Инициализируем состояние сессии
  rhythmSessions.set(sessionId, {
    sessionId,
    secretSequence: pulse,
    clientNoiseProfile: [],
    trustScore: 1.0, // полное доверие при старте
    lastSync: Date.now(),
    driftCompensation: 1.0
  });

  return pulse;
}

/**
 * Проверяет, соответствует ли входящий ритм клиента ожидаемому.
 * Возвращает { valid: boolean, trustScore: number, requiresInterrogation: boolean }.
 */
export function validateRhythm(
  sessionId: string, 
  receivedTimings: number[]
): { valid: boolean; trustScore: number; requiresInterrogation: boolean } {
  const state = rhythmSessions.get(sessionId);
  if (!state) {
    return { valid: false, trustScore: 0, requiresInterrogation: true };
  }

  // 1. Expected timings use only drift compensation — server CPU noise must NOT
  // be added here because server and client run on different hardware entirely.
  const expectedTimings = state.secretSequence.map(t => t * state.driftCompensation);

  // 2. Вычисляем отклонение через Гауссово окно (вместо жесткого порога)
  let totalDeviation = 0;
  for (let i = 0; i < Math.min(expectedTimings.length, receivedTimings.length); i++) {
    const delta = Math.abs(receivedTimings[i] - expectedTimings[i]);
    totalDeviation += delta / expectedTimings[i]; 
  }
  const avgDeviation = totalDeviation / Math.min(expectedTimings.length, receivedTimings.length);

  // 3. Обновляем доверие по Гауссовой функции
  const trustDelta = Math.exp(-avgDeviation * avgDeviation / (2 * DRIFT_WINDOW * DRIFT_WINDOW));
  
  // Плавное обновление: резкое падение при аномалии, медленное восстановление
  if (trustDelta > state.trustScore) {
    state.trustScore = Math.min(1.0, state.trustScore + 0.02); 
  } else {
    state.trustScore = trustDelta; 
  }

  // 4. Декай доверия со временем (если долго не было пакетов)
  const timeSinceLastSync = Date.now() - state.lastSync;
  if (timeSinceLastSync > 30000) { 
    state.trustScore -= TRUST_DECAY_RATE * (timeSinceLastSync / 1000);
  }
  state.lastSync = Date.now();

  // 5. Trim noise profile buffer (populated externally via ramSalt if needed)
  if (state.clientNoiseProfile.length > 100) {
    state.clientNoiseProfile = state.clientNoiseProfile.slice(-50);
  }

  // 6. Автоматическая коррекция дрейфа — capped at 2× base, slow recovery toward 1.0
  if (state.trustScore > 0.8 && avgDeviation > 0.05) {
    state.driftCompensation = Math.min(2.0, state.driftCompensation * (1 + avgDeviation * 0.1));
  } else if (state.trustScore > 0.9 && avgDeviation < 0.02) {
    state.driftCompensation = Math.max(1.0, state.driftCompensation * 0.995); // slow decay back to 1.0
  }

  // 7. Принимаем решение
  const requiresInterrogation = state.trustScore < 0.7 && state.trustScore >= 0.3;
  const valid = state.trustScore >= 0.3;

  // Очищаем сессию при полной потере доверия
  if (state.trustScore < 0.3) {
    rhythmSessions.delete(sessionId);
  }

  return { 
    valid, 
    trustScore: state.trustScore, 
    requiresInterrogation 
  };
}

/**
 * Возвращает текущий коэффициент компенсации дрейфа для сессии.
 */
export function getDriftAdjustment(sessionId: string): number {
  return rhythmSessions.get(sessionId)?.driftCompensation || 1.0;
}

export function getTrustStatus(sessionId: string): number {
    return rhythmSessions.get(sessionId)?.trustScore || 0;
}
