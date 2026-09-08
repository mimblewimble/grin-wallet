# Wallet contracts

Contracts use the same flow for standard sends and invoice transactions. Signing is kept
as an explicit step. Each side can check the slate it receives and its own contribution,
but not commitments added by the other side later in the flow.

A two-party contract is `new`, `sign`, `sign`. A self-spend is `new`, `sign`. There is no
separate `setup` command. Setup is done by `new`, or by the first `sign` when needed.

The owner API provides all four commands. The Rust foreign API also provides `new` and
`sign` for receiving contracts, but they are not exposed by the foreign JSON-RPC API. The
API does not require manual confirmation, so a wallet using it still needs to show the
transaction and ask the user before signing.

The CLI exchanges Slatepacks. The last `sign` broadcasts the transaction unless
`--no-broadcast` is used. `--outfile` overrides the output Slatepack file for `new`, `sign`
and `revoke`.

## Amounts and fees

`--send` and `--receive` are the amount being transferred, before each side pays its own
fee. The sender spends the amount plus its fee. The receiver gets the amount minus its
fee. Without either option, `contract sign` reads both from the first slate. Each side pays
for its own inputs and outputs and a rounded-up share of the kernel fee.

CLI amounts are human readable. Values passed to the API, including `make_outputs`, are in
nanogrin. Outputs requested with `make_outputs` are added together with the output needed
to balance that side of the transaction.

Payjoin is used by default. A receiver adds an input when one is available. An empty wallet
can still receive; the fee is then taken from the received output. `--no-payjoin` prevents
the receiver from adding an input and cannot be used together with `--use-inputs`. Pass one
or more comma-separated output commitments to `--use-inputs` to select specific payjoin inputs.

Inputs and outputs are normally picked when signing. `--add-outputs` picks and locks them
during `new`. Prepared outputs appear as unconfirmed in the wallet, but are only added to
the slate when signing. Using `--use-inputs` or `--make-outputs` during `new` does the same.
Each party chooses `--min_conf` when it first joins and cannot change it later. The same limit
is used for the fee estimate, so any required inputs need enough confirmations at that point.
A value of `0` allows unconfirmed non-coinbase outputs. Open contracts do not reserve funds,
so a late-locked contract can fail if another transaction spends the available outputs first.
Signing then returns `NotEnoughFunds`; revoke and recreate the contract, or use `--add-outputs`
when creating it to reserve inputs.

`contract new --ttl_blocks N` stops contract signing after `N` blocks. Finalized transactions
can still be posted afterward.

`--fee_rate N` uses `N` nanogrin per weight unit for this wallet's fee contribution. Each
wallet chooses its rate when it first joins. Without it, the wallet uses `accept_fee_base`
(500000 by default). The wallet only finalizes when the combined fee meets that minimum. If it
does not, revoke the contract and create a new one.

Each side's account is fixed when it first joins the contract. Changing the active account
later does not affect setup or signing; they use the account stored in the context.

## View and revoke

`view` reads a slate or Slatepack and shows its inputs and outputs when present, fees,
transfer amount and the resulting change to this wallet when known. It also reports whether
the Slatepack was encrypted for this wallet, whether the local transaction is confirmed,
and whether the slate contains unexpected inputs or outputs from this wallet. This last
check is reported as unknown after the private context has been removed, when input features
are missing, or when the slate does not contain a transaction. `view` cannot find a contract
by id.

An encrypted Slatepack can have several recipients. The encryption status only shows that
this wallet could decrypt it.

`revoke` cancels the local transaction. When the wallet added an input, it returns a
self-spend of that input. The caller still has to post it, and either transaction can win
if the original is already in the mempool. When the wallet added no input there is no
replacement transaction. The replacement does not use a higher fee. An interrupted
`revoke` can be run again. Nodes do not currently replace a mempool transaction with the
revoke transaction. Transaction ids belong to an account, so the CLI uses the
account selected with `--account`.

## Current limitations

* Only one or two participants are supported. Larger contracts remain disabled because of
  the [known multi-party attack](https://forum.grin.mw/t/grin-wallet-contract-prototype/9745/18)
* Early payment proofs are available for contracts through the API and CLI. Use `--proof-type`
  and optionally `--memo` (up to 1024 bytes of UTF-8 text). The proof binds the memo's Blake2b hash
* Invoice proofs work with SRS and RSR. Sender-nonce proofs only work with RSR. Both need
  experimental Slate V5; see
  [Early Payment Proofs](https://github.com/mimblewimble/grin-rfcs/pull/70)
* Proof data is stored in the wallet database and cannot be restored from the seed
* There are no contract-specific history, lookup or transport commands
* If writing the signed transaction file fails, the wallet state has already been saved.
  Cancelling the transaction releases the locked inputs

Implementation notes and remaining work are kept in
[`libwallet/src/contract/actions/README.md`](../libwallet/src/contract/actions/README.md).

## References

* [Contract prototype discussion](https://forum.grin.mw/t/grin-wallet-contract-prototype/9745)
* [Manual confirmation proposal](https://github.com/mimblewimble/grin-rfcs/pull/84) (open)
* [Early payment proofs proposal](https://github.com/mimblewimble/grin-rfcs/pull/70) (open)
* [RFC 0006: Payment Proofs](https://github.com/mimblewimble/grin-rfcs/blob/master/text/0006-payment-proofs.md)
* [RFC 0012: Compact Slates](https://github.com/mimblewimble/grin-rfcs/blob/master/text/0012-compact-slates.md)
* [RFC 0015: Slatepack](https://github.com/mimblewimble/grin-rfcs/blob/master/text/0015-slatepack.md)
* [RFC 0017: Fix Fees](https://github.com/mimblewimble/grin-rfcs/blob/master/text/0017-fix-fees.md)
