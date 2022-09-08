# Contract actions

### API endpoints

We introduce 3 new API endpoints `/new, /setup, /sign` each corresponding to a specific action on a contract. In the future we'll add the ability to also `view` a contract and to `revoke` it.

### Rust implementation

Every contract action on a slate is divided in 3 parts:
1. compute the new state
2. save the new state
3. return slate

Putting this into code, it looks like the following:
```rust
// Compute the new state (both of the Slate and the Context)
let (slate, context) = compute(slate, args);
// Atomically commit the new state
contract_utils::save_step(slate, context, ...);
// Return the newly produced slate
return slate;
```

We only allow contribution of custom inputs/outputs when we're doing the setup phase. Once the setup phase is done,
we no longer allow any customization of inputs. This means that the customization can only happen at contract setup phase which is the first time we see the contract.Additionally, if we customize output selection, we immediately pick the inputs/outputs which means it's an early lock. These are however not added to the slate until we reach the 'sign' phase of the contract. Counterparties don't need to see our inputs/outputs before that. This means we always add inputs/outputs only when we have to and never before.

Ideally we'd also separate side effects out of these functions e.g. computing the current_height
or refreshing the outputs with updater::refresh_outputs(...). The current_height could be
communicated through a &ChainState parameter which would collect these values before the call.
Additionally, we could fetch the existing Context before the call to avoid doing db fetch.
Separating side effects until the 'save_step' part would make these functions much easier to test.

#### TODOs

 - make sure to forget the Context when we sign or at least forget the secret keys for it to avoid signing with the same nonce twice
 - make_outputs api should receive nanogrins rather than grin. We have to make the conversion before calling the API
 - sometimes the slatepack outputs with a \n for some reason which makes pasting it register \n as the end of paste and crashes?
 - remove casting decimals, we should accept value in nanogrins (including --make-outputs option), never as 0.1 Grin through the interface. Casting should be left to the gui wallet logic
 - Check casts to/from i64/u64 etc. consider using saturating methods. Make sure conversions are safe.
 - separate side-effects out from the main computations
 - is keys::next_available_key(..) safe from race-conditions? (do we lock?)
 - function add_output_to_ctx has a comment around next_available_key
 - add support for different accounts not just main (check parent_id, parent_key_id, etc. usage)
 - ensure counterparty can't make you overpay fees through num_participants param
 - make sure the stored transaction is saved correctly at each step (TxLogEntry has stored_tx field, check other fields as well)
 - make sure the transaction log contains all the necessary data (check TODO comments on tx log entry functions)
 - graceful error handling
 - setup.rs# TODO: verify that the parent_key_id is consistent
 - replace mutable objects with immutable when possible
 - make sure we lock the wallet when needed (check wallet_lock!() macro that is used in api/owner.rs)
 - add support for more than 2 parties (includes a new 'setup' API endpoint and command)
 - do we avoid using "too recent" outputs? e.g. though with depth < 10
 - remove unneeded imports
 - think if Context.setup_args.net_change type should be u64. If you make it i64, you divide it's size by 2. Perhaps it would be
   better to have a u64 field and another field called 'positive' of type bool.
 - add --no-setup to 'new' command
 - add early-payment proofs. Make sure we have a symmetric variant of a payment proof to avoid having different proofs based on which position you are in the contract signing. Ideally, the position would be irrelevant.
 - what happens if you call contract sign on some slate that was not initiated as a contract slate and has different context values?
 - make sure you handle all the flows with coinbase outputs as well
 - check if they can trick you by providing a slate with different inputs/outputs that are yours
 - remove 'setup' API/CLI
 - move the contract test utilities to a separate contract_utilities file instead of having it in 'common/mod.rs'
 - we have --add-outputs, but we should also lock if we use the --use-inputs param
 - check if contract_accounts_switch.rs is a legit scenario. It might need to return an error if the wallet is trying to sign with a different account

#### Tests
 - test contract_fee (various test around fee contribution with 1 or 2 parties)
 - test save_step functionality (stored tx, context, logs,..)
 - test different output selection in step1 and step3
 - test foreign API for contract new and sign
 - test a case where the receiver doesn't have an input available (either not enough confirmations or no inputs)
 - contract_rsr.rs asserts that you get amount_credited=5, should it subtract the fees?
 - test using more than a single input
 - test that sending then again the same slatepack doesn't produce a new signature (to avoid leaking key)
 - test locking:
	* test that outputs are locked after you sign
	* test early locking when using --make-outputs or --use-inputs etc.
 - test --no-payjoin
 - test accounts
 - test 0-value outputs
 - test that if --no-payjoin is used, this doesn't mean that we early lock (we shouldn't). Same for --make-outputs
 - test slate content through steps
 - test negative cases (not enough funds, using input that doesn't exist, make outputs that go over the value, sign twice,...)

#### DONE
 - Always "late-add" inputs/outputs to the slate
 - _Always_ add a change output, even if the change output ends up being a 0-value output


#### save_step

    // TODO:
    //  - is_signed should be derived from the slate
    //  - Check what happens if the batch fails. Also think about possible race conditions because
    // 	   of the time delay between the id was picked and saved.
    //  - Consider taking ownership of Context here. It should not be used after this is called.


### Side-effects

#### Setup
	// Side-effects:
	//  - height = w.w2n_client().get_chain_tip()?.0;
	//  - maybe_context = w.get_private_context(keychain_mask, sl.id.as_bytes())
	//  - create_contract_ctx -> updater::refresh_outputs(wallet, keychain_mask, parent_key_id, false)?;
	//  - add_outputs -> let current_height = w.w2n_client().get_chain_tip()?.0;
	//  - add_outputs -> contribute_output -> let key_id = keys::next_available_key(wallet, keychain_mask).unwrap();
	//  - TODO: would we need to compute keys::next_available_key for as many outputs as we plan to contribute and pass
	//    them as a param to keep this without side effects?

#### Sign
	// Side-effects:
	//  - contract_utils::check_already_signed -> tx_log_iter
	//  - contract_utils::get_net_change -> context and net_change
	//  - everything from 'setup'