# circuits-helper

Dev tool for computing Poseidon2 hashes needed by the main Thurin circuit.

## Overview

The main circuit requires `iaca_root` and `nullifier` as public inputs. These are Poseidon2 hashes that can't be easily computed outside of a Noir circuit. This helper computes them so you can populate `Prover.toml`.

## What It Computes

| Output | Formula |
|--------|---------|
| `iaca_root` | `Poseidon2([pubkey_x, pubkey_y])` |
| `nullifier` | `Poseidon2([document_number, event_id, iaca_root])` |

## Usage

1. Edit `Prover.toml` with your inputs:

```toml
pubkey_x = [/* 32 bytes */]
pubkey_y = [/* 32 bytes */]
document_number = [/* 32 bytes, padded */]
event_id = "0x1"
```

2. Run the helper:

```bash
nargo execute
```

3. Copy the output values to the main circuit's `Prover.toml`:

```
iaca_root = "0x..."
nullifier = "0x..."
```

## From Monorepo Root

```bash
just circuits-hash
```

## License

Apache-2.0
