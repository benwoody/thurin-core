import { describe, it, expect } from 'vitest';
import { hashEventId } from '../src/contract/index.js';
import { ThurinSBT, ThurinVerifier } from '../src/contract/index.js';
import { THURIN_SBT_ABI, THURIN_VERIFIER_ABI } from '../src/contract/abi.js';
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

describe('THURIN_SBT_ABI', () => {
  const functionNames = THURIN_SBT_ABI
    .filter((entry) => entry.type === 'function')
    .map((entry) => ('name' in entry ? entry.name : ''));

  it('has mint with addressBinding and proofDate', () => {
    const mint = THURIN_SBT_ABI.find(
      (e) => e.type === 'function' && 'name' in e && e.name === 'mint'
    );
    expect(mint).toBeDefined();
    const inputs = (mint as any).inputs.map((i: any) => i.name);
    expect(inputs).toContain('addressBinding');
    expect(inputs).toContain('proofDate');
    expect(inputs).not.toContain('proofTimestamp');
  });

  it('has renew function', () => {
    expect(functionNames).toContain('renew');
  });

  it('has burn function', () => {
    expect(functionNames).toContain('burn');
  });

  it('has getRenewalPrice function', () => {
    expect(functionNames).toContain('getRenewalPrice');
  });

  it('has priceFeed in constructor', () => {
    const ctor = THURIN_SBT_ABI.find((e) => e.type === 'constructor');
    const inputs = (ctor as any).inputs.map((i: any) => i.name);
    expect(inputs).toContain('_priceFeed');
  });

  it('does not have stale tiered pricing functions', () => {
    expect(functionNames).not.toContain('OG_PRICE');
    expect(functionNames).not.toContain('OG_SUPPLY');
    expect(functionNames).not.toContain('EARLY_PRICE');
    expect(functionNames).not.toContain('EARLY_SUPPLY');
    expect(functionNames).not.toContain('mintPrice');
    expect(functionNames).not.toContain('PROOF_VALIDITY_PERIOD');
  });

  it('has correct error names', () => {
    const errorNames = THURIN_SBT_ABI
      .filter((e) => e.type === 'error')
      .map((e) => ('name' in e ? e.name : ''));
    expect(errorNames).toContain('ProofDateFromFuture');
    expect(errorNames).toContain('ProofDateTooOld');
    expect(errorNames).toContain('NoSBTToRenew');
    expect(errorNames).toContain('NoSBTToBurn');
    expect(errorNames).toContain('StalePrice');
    expect(errorNames).not.toContain('ProofExpired');
    expect(errorNames).not.toContain('ProofFromFuture');
  });

  it('Minted event does not include nullifier', () => {
    const minted = THURIN_SBT_ABI.find(
      (e) => e.type === 'event' && 'name' in e && e.name === 'Minted'
    );
    const inputs = (minted as any).inputs.map((i: any) => i.name);
    expect(inputs).not.toContain('nullifier');
    expect(inputs).toContain('referrerTokenId');
  });
});

describe('THURIN_VERIFIER_ABI', () => {
  it('verify has addressBinding and proofDate', () => {
    const verify = THURIN_VERIFIER_ABI.find(
      (e) => e.type === 'function' && 'name' in e && e.name === 'verify'
    );
    const inputs = (verify as any).inputs.map((i: any) => i.name);
    expect(inputs).toContain('addressBinding');
    expect(inputs).toContain('proofDate');
    expect(inputs).not.toContain('proofTimestamp');
  });

  it('has PROOF_DATE_TOLERANCE_DAYS instead of PROOF_VALIDITY_PERIOD', () => {
    const names = THURIN_VERIFIER_ABI
      .filter((e) => e.type === 'function')
      .map((e) => ('name' in e ? e.name : ''));
    expect(names).toContain('PROOF_DATE_TOLERANCE_DAYS');
    expect(names).not.toContain('PROOF_VALIDITY_PERIOD');
  });
});

describe('ThurinSBT', () => {
  const mockClient = {} as any;
  const address = '0x1234567890123456789012345678901234567890' as const;

  it('burn() requires wallet client', async () => {
    const sbt = new ThurinSBT(address, mockClient);
    await expect(sbt.burn()).rejects.toThrow('WalletClient required');
  });

  it('renew() requires wallet client', async () => {
    const sbt = new ThurinSBT(address, mockClient);
    const mockProof = {
      proof: '0x1234' as any,
      publicInputs: {
        nullifier: '0x01' as any,
        addressBinding: '0x02' as any,
        proofDate: 20260205,
        eventId: '0x03' as any,
        iacaRoot: '0x04' as any,
        boundAddress: address,
        proveAgeOver21: true,
        proveAgeOver18: false,
        proveState: false,
        provenState: '',
      },
    };
    await expect(sbt.renew(mockProof)).rejects.toThrow('WalletClient required');
  });

  it('mint() requires wallet client', async () => {
    const sbt = new ThurinSBT(address, mockClient);
    const mockProof = {
      proof: '0x1234' as any,
      publicInputs: {
        nullifier: '0x01' as any,
        addressBinding: '0x02' as any,
        proofDate: 20260205,
        eventId: '0x03' as any,
        iacaRoot: '0x04' as any,
        boundAddress: address,
        proveAgeOver21: true,
        proveAgeOver18: false,
        proveState: false,
        provenState: '',
      },
    };
    await expect(sbt.mint(mockProof)).rejects.toThrow('WalletClient required');
  });
});

describe('ThurinVerifier', () => {
  const mockClient = {} as any;
  const address = '0x1234567890123456789012345678901234567890' as const;

  it('verify() requires wallet client', async () => {
    const verifier = new ThurinVerifier(address, mockClient);
    const mockProof = {
      proof: '0x1234' as any,
      publicInputs: {
        nullifier: '0x01' as any,
        addressBinding: '0x02' as any,
        proofDate: 20260205,
        eventId: '0x03' as any,
        iacaRoot: '0x04' as any,
        boundAddress: address,
        proveAgeOver21: true,
        proveAgeOver18: false,
        proveState: false,
        provenState: '',
      },
    };
    await expect(verifier.verify(address, mockProof)).rejects.toThrow(
      'WalletClient required'
    );
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
