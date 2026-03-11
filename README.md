# open-prover

A Rust workspace for zero-knowledge proof execution and verification, supporting RISC0 and SP1 proving systems.

## Architecture

```
open-prover/
├── common/              # Shared utilities (serialization, storage, URI resolver)
├── risc0/               # RISC0 prover + gRPC server
├── sp1/                 # SP1 prover
└── tools/
    └── risc0-fixtures/  # RISC0 test fixture generator
```

### common

Shared infrastructure layer used across the project.

- **Serialization** — Bincode, JSON, MessagePack format support
- **Storage** — Abstract storage trait with filesystem implementation
- **URI Resolver** — `data://`, `http(s)://`, `efs://` scheme support

### risc0

gRPC service implementation for the RISC0 ZK proving system.

**gRPC Endpoints:**

| RPC | Description |
|-----|-------------|
| `Execute` | Execute RISC-V ELF binary (streaming) |
| `ProveSegment` | Generate segment proof |
| `ProveKeccak` | Generate keccak hash proof |
| `Join` | Combine two receipts |
| `Union` | Create receipt union |
| `Resolve` | Resolve assumptions |
| `Finalize` | Generate final receipt |
| `Stark2Snark` | Convert STARK to SNARK |

### sp1

SP1 proving system implementation.

- Setup, Prove, Recursion, Sharding
- End-to-end pipelines: Compressed, Groth16, PLONK, Wrap
- Optional GPU acceleration via Moongate

## Getting Started

### Prerequisites

- Rust (with resolver v3 support)
- [RISC0 toolchain](https://dev.risczero.com/api/zkvm/install)
- [SP1 toolchain](https://docs.succinct.xyz/getting-started/install.html)
- Protocol Buffers compiler (`protoc`)

### Build

```bash
cargo build --release
```

With GPU acceleration:

```bash
cargo build --release --features cuda
```

### Run (RISC0 gRPC Server)

```bash
cargo run --release --package risc0
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_PATH` | `efs` | File storage root directory |
| `GRPC_ADDR` | `0.0.0.0:50051` | gRPC server address |

### Generate Test Fixtures

```bash
cargo run --release --package risc0-fixtures
```

## License

All rights reserved.
