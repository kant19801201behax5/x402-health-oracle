import { describe, it, expect } from 'vitest'
import {
  WelfordProfile,
  klDivergence,
  normalizeDistribution,
  compareToProfile,
} from '../src/welford'

describe('WelfordProfile', () => {
  it('accumulates mean and variance correctly', () => {
    const p = new WelfordProfile()
    const data = [10, 20, 30, 40, 50]
    for (const v of data) p.update(v)
    expect(p.count).toBe(5)
    expect(p.mean).toBeCloseTo(30, 10)
    expect(p.variance).toBeCloseTo(250, 10)
  })

  it('single sample has zero variance', () => {
    const p = new WelfordProfile()
    p.update(42)
    expect(p.count).toBe(1)
    expect(p.mean).toBe(42)
    expect(p.variance).toBe(0)
  })

  it('isStable requires minSamples', () => {
    const p = new WelfordProfile()
    for (let i = 0; i < 99; i++) p.update(i)
    expect(p.isStable(100)).toBe(false)
    p.update(99)
    expect(p.isStable(100)).toBe(true)
  })

  it('serializes and restores via JSON', () => {
    const p = new WelfordProfile()
    for (let i = 0; i < 200; i++) p.update(10 + Math.sin(i) * 2)
    const json = p.toJSON()
    const restored = WelfordProfile.fromJSON(json)
    expect(restored.count).toBe(p.count)
    expect(restored.mean).toBeCloseTo(p.mean, 10)
    expect(restored.variance).toBeCloseTo(p.variance, 5)
  })

  it('toDistribution returns normalized bins', () => {
    const p = new WelfordProfile()
    for (let i = 0; i < 200; i++) p.update(50 + (Math.random() - 0.5) * 10)
    const dist = p.toDistribution(20)
    expect(dist.length).toBe(20)
    const sum = dist.reduce((a, b) => a + b, 0)
    expect(sum).toBeCloseTo(1, 2)
  })
})

describe('klDivergence', () => {
  it('is zero for identical distributions', () => {
    const p = [0.25, 0.25, 0.25, 0.25]
    expect(klDivergence(p, p)).toBeCloseTo(0, 5)
  })

  it('is positive for different distributions', () => {
    const p = [0.9, 0.05, 0.03, 0.02]
    const q = [0.25, 0.25, 0.25, 0.25]
    expect(klDivergence(p, q)).toBeGreaterThan(0)
  })

  it('throws on mismatched lengths', () => {
    expect(() => klDivergence([1], [1, 2])).toThrow()
  })
})

describe('normalizeDistribution', () => {
  it('sums to 1', () => {
    const result = normalizeDistribution([3, 1, 2, 4])
    expect(result.reduce((a, b) => a + b, 0)).toBeCloseTo(1, 10)
  })

  it('handles all-zero input', () => {
    const result = normalizeDistribution([0, 0, 0])
    expect(result).toEqual([0, 0, 0])
  })
})

describe('compareToProfile', () => {
  it('returns low KL for same-distribution samples', () => {
    const p = new WelfordProfile()
    const base = 50
    for (let i = 0; i < 500; i++) p.update(base + (Math.random() - 0.5) * 4)

    const similar = Array.from({ length: 100 }, () => base + (Math.random() - 0.5) * 4)
    const kl = compareToProfile(p, similar)
    expect(kl).toBeLessThan(0.5)
  })

  it('returns high KL for different-distribution samples', () => {
    const p = new WelfordProfile()
    for (let i = 0; i < 500; i++) p.update(50 + (Math.random() - 0.5) * 2)

    const different = Array.from({ length: 100 }, () => 200 + Math.random() * 50)
    const kl = compareToProfile(p, different)
    expect(kl).toBeGreaterThan(1)
  })

  it('returns 0 when profile not stable', () => {
    const p = new WelfordProfile()
    p.update(10)
    expect(compareToProfile(p, [10, 20, 30])).toBe(0)
  })
})
