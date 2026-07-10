# Wallet + node integration tests

Multi-process tests that run a real Grin node (`grin_servers`) together with
`grin-wallet` foreign/owner HTTP listeners.

**Node-only** multi-server suites (seeding, propagation, body sync, stratum)
live in [mimblewimble/grin](https://github.com/mimblewimble/grin) under
`integration/` ([#2957](https://github.com/mimblewimble/grin/issues/2957)).

In-process wallet unit/integration coverage (mock node via `WalletProxy`)
remains under `controller/tests/`.

## Run

```bash
cd integration
cargo test --release -- --test-threads=1
```

Serial execution avoids port and RocksDB races.
