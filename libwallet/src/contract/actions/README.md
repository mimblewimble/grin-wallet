# Contract actions

The workflow, command behaviour and current limitations are documented in
[`doc/contracts.md`](../../../../doc/contracts.md). This file tracks implementation details
and unfinished work.

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

`save_step` writes the context, tx log, outputs and input locks in one LMDB batch. The
signed transaction is stored separately outside LMDB and cannot share that batch.

Input and output choices are made during setup. The confirmation limit is stored in the local
context because it is also used for the fee estimate. `add_outputs` selects and locks inputs
during setup; otherwise this happens during signing. The inputs and outputs are only added to
the slate when signing, so the counterparty does not see them earlier.

Ideally we'd also separate side effects out of these functions e.g. computing the current_height
or refreshing the outputs with updater::refresh_outputs(...). The current_height could be
communicated through a &ChainState parameter which would collect these values before the call.
Setup still reads an existing Context again; passing it through would avoid that DB read.
Separating side effects until the 'save_step' part would make these functions much easier to test.

`new` and `sign` stay on the Rust Foreign API for now. They are not exposed over JSON-RPC
without a user confirmation step.

#### TODOs

 - Add RBF support to the Grin node before raising the replacement fee when `revoke`
   races a transaction already in the mempool.
 - Add a Grin node API for kernel lookup by MMR index, then use the witness index instead
   of searching by commitment.
 - Expose the kernel feature constants from `grin_core` and reuse them here.
 - Move payment-proof creation and verification onto `Slate` so it can also be used
   outside contracts and is versioned with the slate format.
 - Add contract history, lookup and transport.
 - Separate side effects out from the computation, as described above.
 - Store transactions in LMDB so they can be committed with the wallet state.
 - Revisit automatic receive signing once there is a user confirmation step.
 - Revisit `remove_other_sigdata` before allowing more than two participants.

### Side-effects

#### Setup
	// Persisting setup::compute() requires verify_not_signed first
	// Side-effects:
	//  - contract_utils::verify_not_signed -> tx_log_iter
	//  - height = w.w2n_client().get_chain_tip()?.0;
	//  - maybe_context = w.get_private_context(keychain_mask, sl.id.as_bytes())
	//  - create_contract_ctx -> updater::refresh_outputs(wallet, keychain_mask, parent_key_id, false)?;
	//  - add_outputs -> let current_height = w.w2n_client().get_chain_tip()?.0;
	//  - add_outputs -> add_outputs_to_ctx -> w.next_child_for(...)

#### Sign
	// Side-effects:
	//  - contract_utils::verify_not_signed -> tx_log_iter
	//  - sign -> w.get_private_context(...)
	//  - verify_incoming_own_commitments -> w.iter()
	//  - verify_own_commitments -> w.get(...)
	//  - everything from 'setup'
