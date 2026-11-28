# Stateless receive

By default a wallet answering a standard send request (`receive_tx` on the
Foreign API, `grin-wallet receive`, the Tor/HTTP listener) stores a pending
output, a transaction log entry and the slate state, and allocates the next
sequential child key, before it knows whether the sender will ever finalize
the transaction. Anyone who can reach a listening wallet can therefore make
it write an unbounded number of records that never confirm.

With stateless receive the wallet builds the same `Standard2` response
without writing records for the payment attempt. The output only becomes
wallet state once it is on chain.

## Enabling

In `grin-wallet.toml`:

```toml
[wallet]
stateless_receive = true
# optional, in nanogrin
stateless_receive_min_amount = 100000000
```

This setting applies to the dedicated HTTP/Tor listener started by
`grin-wallet listen`. In this mode the listener serves
`check_version` and `receive_tx` only. Use the ordinary receiver or
owner workflow for manual receives, invoices, mining, or finalization.
The mode is off by default and does not change the slate format.

For a fresh wallet, listener startup durably requests a full first scan
before it can issue a response. Starting the listener does not move the
scan cursor. Wallets that already have scan coverage continue from it.

Embedders can opt in explicitly using `Foreign::set_stateless_receive`.
The first successful reply also ensures that a fresh wallet has requested a
full scan. Embedders choose which RPC methods to expose.

The scanner fixes the range at startup and checks the body tip around each
batch of UTXO reads. The cursor records both the range boundary and the body
tip at which the batch was observed. That tip must still be on the node's
chain before the next batch or a resumed scan. A legacy or stale cursor
without verifiable coverage triggers a full scan. To repair a skipped
first scan manually, run `scan` without a starting height to recover any
still-unspent outputs.

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

Restoring from seed works the same way. Each import batch commits the
account, applicable sequential child index, outputs, and receipts together.
A subsequent scan also repairs account metadata for records saved by an
older interrupted import. It preserves existing account labels and never
decreases the sequential child index.

## What is different from a regular receive

* Nothing is shown until the transaction is on chain: no `Awaiting
  Finalization` output and no unconfirmed transaction log entry, so there is
  also nothing to cancel.
* The transaction log entry created by the scan has no slate id, exactly like
  any other entry restored from the chain.
* There is no duplicate check. Receiving the same slate twice returns two
  different responses. If a sender finalizes both with the same inputs,
  the resulting transactions conflict.
* The receive-only listener has no invoice or finalization operations.
  The ordinary wallet's invoice workflow still creates its output when
  the payee issues the invoice.

## Reorganizations and spending

Ordinary wallet refreshes recheck stateless outputs, including those
previously marked spent. The wallet
records the creation block reported by the node and the original incoming
log entry when it finds an output. This association survives locking the
output for an outgoing transaction. A missing output whose block is still
on the node's selected chain is spent. If the old block was replaced, the
receipt loses confirmation and the output is excluded from spendable funds.
This withdraws the old inclusion; an output re-included and already spent
elsewhere may still be absent from the UTXO set. A pending outgoing lock
survives these observations. Cancelling it keeps an absent input unavailable.
If an input from a previously confirmed outgoing transaction returns, the
wallet checks the outgoing kernel against the same chain view. When that
kernel is absent, the original input stays reserved, the outgoing transaction
becomes unconfirmed and missing change becomes unavailable. The wallet
updates these records together. The sender can cancel the outgoing
transaction or wait for its kernel to return.
If the original block could not be established (for example, older wallet
data or a node client without header lookup), absence leaves confirmation
unknown. A later observation can confirm the same receipt again, including
when the output's PMMR position has changed. These observations use the
wallet's usual trust in a single coherent configured node. Tip checks
detect disagreeing responses but do not bind independent RPCs to an
atomic node snapshot.

During a refresh, previously read header hashes are reused only if the
node's body tip is the same or the previous checked body tip is still
on its selected chain. A fork at or before the cached tip causes the
relevant headers to be fetched again. This cache is in memory. Output
lookup still covers spent stateless commitments: a commitment can return
even on a chain that only grew.

## Compatibility

The wallet uses the existing unavailable output status on disk and stores
the reason separately. Older wallet binaries can decode these records
but do not show the distinction between a replaced block and an unknown
confirmation. A legacy output that no longer has a link to its original
receipt cannot recover that link from chain alone.

Scanning for these outputs needs a wallet that knows about the range. An
older wallet restoring the same seed will find the outputs (the range proof
rewinds as usual) but will file each of them under a newly created
`account_N` at the output's BIP32 parent path instead of under the account
it was received into. The outputs are still recognised as the wallet's own,
but they do not show up in the balance of the account they were sent to.

## Listener resource limits

Building a response costs an output, a range proof and a signature. The
dedicated stateless listener uses a shared in-memory quota of four calls per
second, with a burst capacity of eight. The first credit is charged before
reading the HTTP POST. A JSON-RPC batch reserves credit for every element,
including notifications, before any call in the batch can run. One dispatch
runs at a time. Requests that arrive while it is busy receive a response
immediately, with no queue of pending wallet work.

The listener reads at most four request bodies concurrently. Each body has a
256 KiB limit and a 10-second read deadline. A batch can contain at most eight
calls. Quota exhaustion returns HTTP 429 with a two-second `Retry-After`.
Busy readers or dispatch return HTTP 503 with a one-second `Retry-After`.
An oversized body returns 413, a read timeout returns 408, and malformed
JSON or an oversized batch returns 400.
The Arti and SOCKS clients report 429 and 503 with a numeric
`Retry-After` value when provided. They leave the decision to resend to
the sender.

These limits apply to the dedicated HTTP/Tor listener. Embedders using the
stateless API directly choose their own limits. An optional Tor return
callback can occupy the dispatch slot while it waits. Connection admission
and fair sharing among senders are separate from the wallet's shared quota.

`stateless_receive_min_amount` addresses a different nuisance: transactions
that do confirm but carry dust. Requests below the minimum are refused before
anything is built.
