import { describe, it, expect } from 'vitest';
import { hashEventId } from '../src/contract/index.js';
import { Thurin } from '../src/index.js';

describe('hashEventId', () => {
  it('produces consistent hashes', () => {
    const hash1 = hashEventId('my-app-2026');
    const hash2 = hashEventId('my-app-2026');
    expect(hash1).toBe(hash2);
  });

  it('produces different hashes for different inputs', () => {
    const hash1 = hashEventId('my-app-2026');
    const hash2 = hashEventId('my-app-2027');
    expect(hash1).not.toBe(hash2);
  });

  it('returns a valid hex string', () => {
    const hash = hashEventId('test-event');
    expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
  });
});

describe('Thurin', () => {
  const mockAddresses = {
    sbt: '0x1234567890123456789012345678901234567890' as const,
    verifier: '0x2345678901234567890123456789012345678901' as const,
    points: '0x3456789012345678901234567890123456789012' as const,
  };

  it('initializes with config', () => {
    const thurin = new Thurin({
      chainId: 8453,
      addresses: mockAddresses,
    });

    expect(thurin).toBeDefined();
    expect(thurin.getSBT()).toBeDefined();
    expect(thurin.getVerifier()).toBeDefined();
    expect(thurin.getPoints()).toBeDefined();
  });

  it('throws for unsupported chain', () => {
    expect(() => {
      new Thurin({
        chainId: 99999,
        addresses: mockAddresses,
      });
    }).toThrow('Unsupported chain ID');
  });

  it('supports Base mainnet', () => {
    const thurin = new Thurin({
      chainId: 8453,
      addresses: mockAddresses,
    });
    expect(thurin).toBeDefined();
  });

  it('supports Base Sepolia', () => {
    const thurin = new Thurin({
      chainId: 84532,
      addresses: mockAddresses,
    });
    expect(thurin).toBeDefined();
  });

  it('supports Arbitrum', () => {
    const thurin = new Thurin({
      chainId: 42161,
      addresses: mockAddresses,
    });
    expect(thurin).toBeDefined();
  });
});
