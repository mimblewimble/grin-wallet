# Wallet + node integration tests

Live **node + wallet** tests that run a real Grin node (`grin_servers` from the
pinned `grin` submodule) together with `grin-wallet` **foreign HTTP** listeners
in the same process (threaded). Coverage focuses on:

- mining coinbase into a wallet foreign listener and reading summary via the Owner API
- two-wallet slate send/receive over the foreign HTTP path (`receive_tx` JSON-RPC)

Owner HTTP and true multi-process (separate OS processes) coverage is not in
this crate yet; Owner calls here use the in-process Owner API while the
**foreign receive path is exercised over HTTP**.

**Node-only** multi-server suites (seeding, propagation, body sync, stratum) are
being revived separately in open PR
[mimblewimble/grin#3910](https://github.com/mimblewimble/grin/pull/3910)
([#2957](https://github.com/mimblewimble/grin/issues/2957)). They are not yet
merged into `grin`.

In-process wallet unit/integration coverage (mock node via `WalletProxy`)
remains under `controller/tests/`.

## Run

```bash
cd integration
cargo test --release -- --test-threads=1
```

Serial execution avoids races on fixed ports and data directories.
