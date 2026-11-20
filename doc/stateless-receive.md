# Stateless receive

By default a wallet answering a standard send request (`receive_tx` on the
Foreign API, `grin-wallet receive`, the Tor/HTTP listener) stores a pending
output, a transaction log entry and the slate state, and allocates the next
sequential child key, before it knows whether the sender will ever finalize
the transaction. Anyone who can reach a listening wallet can therefore make
it write an unbounded number of records that never confirm.

With stateless receive the wallet builds the same `Standard2` response but
writes nothing. The output only becomes wallet state once it is on chain.

## Enabling

In `grin-wallet.toml`:

```toml
[wallet]
stateless_receive = true
# optional, in nanogrin
stateless_receive_min_amount = 100000000
```

Callers embedding the wallet can use `Foreign::set_stateless_receive`
instead, which takes precedence over the configuration file.

The setting is off by default and only changes how this wallet receives.
Nothing changes for the sender, and no slate or protocol change is involved.

## How it works

The recipient output is not derived from the account's sequential range
`m/a/0/n` but from

```
m/a/(0x40000000 | r0)/r1/r2
```

where `a` is the account, `r0` is 27 random bits and `r1`, `r2` are 31 random
bits each (89 bits in total), drawn fresh for every request. Like every
wallet output, its key path is embedded in the output's rewindable range
proof. When the transaction confirms, the wallet's regular scan (which runs
as part of every wallet update) rewinds the proof, recognises the path as a
stateless receive, and adds the output and a confirmed `Received Tx` entry to
account `a`. The account's sequential child index is not touched.

Restoring from seed works the same way: the scan finds the outputs and files
them under the account they were received into.

## What is different from a regular receive

* Nothing is shown until the transaction is on chain: no `Awaiting
  Finalization` output and no unconfirmed transaction log entry, so there is
  also nothing to cancel.
* The transaction log entry created by the scan has no slate id, exactly like
  any other entry restored from the chain.
* There is no duplicate check. Receiving the same slate twice returns two
  different responses; since both spend the sender's inputs, at most one of
  them can confirm.
* Invoice transactions are not affected. The payee of an invoice creates its
  output when it issues the invoice, which is stateful by nature.

## Compatibility

Scanning for these outputs needs a wallet that knows about the range. An
older wallet restoring the same seed will find the outputs (the range proof
rewinds as usual) but will file each of them under a newly created
`account_N` at the output's BIP32 parent path instead of under the account
it was received into. The outputs are still recognised as the wallet's own,
but they do not show up in the balance of the account they were sent to.

## What it does not solve

Building the response still costs the receiver an output, a range proof and
a signature. Stateless receive removes the persistent state an unauthenticated
sender can create; it does not limit the CPU a flood of requests consumes, so
rate limiting or a client puzzle in front of the listener remain useful.

`stateless_receive_min_amount` addresses a different nuisance: transactions
that do confirm but carry dust. Requests below the minimum are refused before
anything is built.
