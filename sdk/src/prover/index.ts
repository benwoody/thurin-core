export {
  initProver,
  isProverInitialized,
  generateProof,
  verifyProofLocally,
  destroyProver,
} from './prover.js';

export type {
  CompiledCircuit,
  Credential,
  ProofGenerationOptions,
  GeneratedProof,
} from './types.js';
