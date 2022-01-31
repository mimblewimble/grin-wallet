// Copyright 2022 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contract building utility functions

use crate::contract::selection::{prepare_outputs, verify_selection_consistency};
use crate::contract::types::{ContractSetupArgsAPI, OutputSelectionArgs};

use crate::grin_core::libtx::proof::ProofBuilder;
use crate::grin_core::libtx::{build, tx_fee};
use crate::grin_keychain::{Identifier, Keychain};
use crate::grin_util::secp::key::SecretKey;
use crate::internal::{keys, updater};
use crate::slate::{Slate, SlateState};
use crate::types::{Context, NodeClient, TxLogEntryType, WalletBackend};
use crate::{Error, OutputData, OutputStatus, TxLogEntry};
use grin_core::core::FeeFields;
use uuid::Uuid;

/// Creates a context for a contract
pub fn create_contract_ctx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	// TODO: compare with &InitTxArgs to see if any information is missing
	setup_args: &ContractSetupArgsAPI,
	parent_key_id: &Identifier,
	use_test_rng: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("Creating a new contract context");
	// sender should always refresh outputs
	updater::refresh_outputs(w, keychain_mask, parent_key_id, false)?;

	// Fee contribution estimation
	let net_change = setup_args.net_change.unwrap();
	// select inputs to estimate fee cost
	let (inputs, _, my_fee) =
		prepare_outputs(w, &parent_key_id, current_height, &setup_args, None)?;
	// The number of outputs we expect is the number of custom outputs plus one change output
	debug!(
		"My fee contribution estimation: {} for n_inputs: {}, n_outputs: {}, n_kernels: {}, num_participants: {}",
		my_fee.fee(), inputs.len(), setup_args.selection_args.num_custom_outputs() + 1, 1, setup_args.num_participants
	);
	// Make sure `my_fee < net_change` holds for the receiver. This can't be true for a self-spend, because nobody
	// has a net_change > 0 which makes a self-spend ok to be a net negative when fees are included.
	if net_change > 0 && my_fee.fee() > net_change.abs() as u64 {
		panic!(
			"My contribution as a receiver would be net negative. my_fee: {}, net_change: {}",
			my_fee.fee(),
			net_change
		);
	}
	// Add my share of fee contribution to the slate fees
	slate.fee_fields = FeeFields::new(0, slate.fee_fields.fee() + my_fee.fee())?;
	debug!("Slate.fee: {}", slate.fee_fields.fee());

	// Create a Context for this slate
	let keychain = w.keychain(keychain_mask)?;
	// TODO: it seems 'is_initiator: true' is only used in test_rng. Do we care about this?
	let mut context = Context::new(keychain.secp(), &parent_key_id, use_test_rng, true);
	// Context.fee will hold _our_ fee contribution and not the total slate fee
	context.fee = my_fee.as_opt();
	// Context.amount is not used in contracts, but we set it anyway.
	context.amount = slate.amount;
	// TODO: looking at what uses Context.late_lock_args, it seems only the args in SelectionArgs are used except
	// for args.ttl_blocks. Is this needed? Can we refactor this?
	context.setup_args = Some(setup_args.clone());
	debug!(
		"Setting Context.net_change as: {}",
		context.get_net_change()
	);

	Ok(context)
}

/// Add payment proof data to slate
pub fn add_payment_proof_data(slate: &mut Slate) -> Result<(), Error> {
	// TODO: Implement. Consider adding this function to the Slate itself so they can easily be versioned
	// e.g. slate.add_payment_proof_data()
	Ok(())
}

/// Verify payment proof signature
pub fn verify_payment_proof_sig(slate: &Slate) -> Result<(), Error> {
	// TODO: Implement. Consider adding this function to the Slate itself so they can easily be versioned
	// e.g. slate.verify_payment_proof_sig()
	Ok(())
}

/// Add outputs to a contract (including spent outputs which get locked)
pub fn add_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract_utils::add_outputs => call");
	// Do nothing if we have already contributed our outputs. The assumption is that if this was done,
	// our output contribution is complete.
	if context.output_ids.len() > 0 || context.input_ids.len() > 0 {
		debug!("contract_utils::add_outputs => outputs have already been added, returning.");
		return Ok(());
	}
	let setup_args = context.setup_args.as_ref().unwrap();
	debug!("contract_utils::add_outputs => adding outputs");
	let current_height = w.w2n_client().get_chain_tip()?.0;
	let parent_key_id = &context.parent_key_id;

	// Select inputs for which `Σmy_inputs >= Σmy_outputs + my_fee_cost` holds. Uses committed fee if present.
	let (inputs, my_output_amounts, my_fee) = prepare_outputs(
		&mut *w,
		parent_key_id,
		current_height,
		&setup_args,
		context.fee,
	)?;
	assert_eq!(my_fee.fee(), context.fee.unwrap().fee(), "my_fee!=ctx.fee");
	// Add selected/created inputs/outputs to the context
	add_inputs_to_ctx(context, &inputs)?;
	add_output_to_ctx(w, keychain_mask, context, my_output_amounts)?;

	Ok(())
}

/// Add inputs to Context
pub fn add_inputs_to_ctx(context: &mut Context, inputs: &Vec<OutputData>) -> Result<(), Error> {
	debug!("contract_utils::add_inputs_to_ctx => adding inputs to context");
	for input in inputs {
		context.add_input(&input.key_id, &input.mmr_index, input.value);
		debug!(
			"contract_utils::add_inputs_to_ctx => input id: {}, value:{}",
			&input.key_id, input.value
		);
	}

	Ok(())
}

/// Add output to Context
pub fn add_output_to_ctx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	context: &mut Context,
	amounts: Vec<u64>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	for amount in amounts {
		// TODO: it seems like next_available_key does not respect the parent_key_id. Check if it does, it probably should?
		//  A late-lock might have a different account set to active than the one that was set to the Context
		let key_id = keys::next_available_key(w, keychain_mask).unwrap();
		context.add_output(&key_id, &None, amount);
		debug!(
			"contract_utils::add_output_to_ctx => added output to context. Output id: {}, amount: {}",
			key_id.clone(),
			amount
		);
	}
	Ok(())
}

/// Adds inputs and outputs to slate
pub fn contribute_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	add_inputs_to_slate(w, keychain_mask, slate, context)?;
	add_outputs_to_slate(w, keychain_mask, slate, context)?;
	Ok(())
}

/// Contribute inputs to slate
pub fn add_inputs_to_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract_utils::add_inputs_to_slate => adding inputs to slate");
	let keychain = w.keychain(keychain_mask)?;
	let batch = w.batch(keychain_mask)?;
	for (key_id, mmr_index, _) in context.get_inputs() {
		// We have no information if the input is a coinbase or not, so we fetch the data from DB
		let coin = batch.get(&key_id, &mmr_index).unwrap();
		if coin.is_coinbase {
			slate.add_transaction_elements(
				&keychain,
				&ProofBuilder::new(&keychain),
				vec![build::coinbase_input(coin.value, coin.key_id.clone())],
			)?;
			debug!(
				"contract_utils::add_inputs_to_slate => added coinbase input id: {}, value: {}",
				coin.key_id.clone(),
				coin.value
			);
		} else {
			slate.add_transaction_elements(
				&keychain,
				&ProofBuilder::new(&keychain),
				vec![build::input(coin.value, coin.key_id.clone())],
			)?;
			debug!(
				"contract_utils::add_inputs_to_slate => added regular input id: {}, value: {}",
				coin.key_id.clone(),
				coin.value
			);
		}
	}

	Ok(())
}

/// Contribute outputs to slate
pub fn add_outputs_to_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract_utils::add_outputs_to_slate => start");
	let keychain = w.keychain(keychain_mask)?;
	// Iterate over outputs in the Context and add the same output to the slate
	for (key_id, _, amount) in context.get_outputs() {
		slate.add_transaction_elements(
			&keychain,
			&ProofBuilder::new(&keychain),
			vec![build::output(amount, key_id.clone())],
		)?;
		debug!(
			"contract_utils::add_outputs_to_slate => added output to slate. Output id: {}, amount: {}",
			key_id.clone(),
			amount
		);
	}

	Ok(())
}

/// Creates an initial TxLogEntry without input/output or kernel information
pub fn create_tx_log_entry(
	slate: &Slate,
	net_change: i64,
	parent_key_id: Identifier,
	log_id: u32,
) -> Result<TxLogEntry, Error> {
	let log_type = if net_change > 0 {
		TxLogEntryType::TxReceived
	} else {
		TxLogEntryType::TxSent
	};
	let mut t = TxLogEntry::new(parent_key_id.clone(), log_type, log_id);
	// TODO: TxLogEntry has stored_tx field. Check what this needs to be set to and check other fields as well

	t.tx_slate_id = Some(slate.id);
	if net_change > 0 {
		t.amount_credited = net_change as u64;
	} else {
		t.amount_debited = -net_change as u64;
	}
	t.ttl_cutoff_height = match slate.ttl_cutoff_height {
		0 => None,
		n => Some(n),
	};

	Ok(t)
}

/// Updates TxLogEntry for a contract with information available in the 'sign' step
pub fn update_tx_log_entry<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	context: &Context,
	tx_log_entry: &mut TxLogEntry,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// This is expected to be called when we are signing the contract and have already contributed inputs & outputs
	let keychain = wallet.keychain(keychain_mask)?;
	let current_height = wallet.w2n_client().get_chain_tip()?.0;
	// We have already contributed inputs and outputs so we know how much of each we contribute
	tx_log_entry.num_outputs = context.output_ids.len();
	tx_log_entry.num_inputs = context.input_ids.len();
	tx_log_entry.fee = context.fee;
	// Set kernel information
	match slate.calc_excess(keychain.secp()) {
		Ok(e) => tx_log_entry.kernel_excess = Some(e),
		Err(_) => panic!("We can't update tx log entry. Excess could not be computed."),
	};
	tx_log_entry.kernel_lookup_min_height = Some(current_height);

	Ok(())
}

/// Get net_change value. This is obtained either from the Context.net_change or the setup_args.net_change
pub fn get_net_change<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	setup_args_net_change: Option<i64>,
) -> Result<i64, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut expected_net_change: Option<i64> = setup_args_net_change;
	match w.get_private_context(keychain_mask, slate.id.as_bytes()) {
		Ok(ctx) => {
			debug!("contract::sign => context found");
			// We have a context so we must have agreed on a certain net_change value in Context.net_change.
			// If we have both Context.net_change and setup_args.net_change, then they must be equal.
			match expected_net_change {
				Some(args_net_change) => {
					if ctx.get_net_change() != args_net_change {
						panic!(
							"Expected net change mismatch! Context.net_change: {}, setup_args.net_change: {}",
							ctx.get_net_change(), args_net_change
						);
					}
				}
				None => (),
			}
			expected_net_change = Some(ctx.get_net_change());
		}
		Err(err) => debug!("contract::sign => context not found"),
	};

	// Fail if net_change was not passed to setup_args and was also not present in the context.
	// This means it has not been explicitly agreed on and we require the user to pass it.
	if expected_net_change.is_none() {
		return Err(Error::GenericError(
			"You did not agree on the expected net difference.".into(),
		)
		.into());
	}

	Ok(expected_net_change.unwrap())
}

/// Transition the slate state to the next one
pub fn transition_slate_state(slate: &mut Slate) -> Result<(), Error> {
	// We don't really use these states right now apart from leaving it to derive expected net_change.
	// This suggests these can't be used for manipulation. It doesn't hurt to think a bit more if that's the case.
	let new_state = match slate.state {
		SlateState::Invoice1 => SlateState::Invoice2,
		SlateState::Invoice2 => SlateState::Invoice3,
		SlateState::Standard1 => SlateState::Standard2,
		SlateState::Standard2 => SlateState::Standard3,
		_ => {
			debug!("Slate.state: {}", slate.state);
			SlateState::Standard3
		}
	};
	slate.state = new_state;
	// NOTE: It's possible to never reach the step3. A self-spend has only 2 steps: new -> sign.
	Ok(())
}

/// Add partial signature to the slate. This is a sign & forget pubkey+nonce implementation.
pub fn add_partial_signature<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract_utils::add_partial_signature => adding partial signature");
	let keychain = w.keychain(keychain_mask)?;
	slate.add_partial_sig(&keychain, &context)?;
	debug!("contract_utils::add_partial_signature => done");

	Ok(())
}

/// We can finalize if all partial sigs are present
pub fn can_finalize(slate: &Slate) -> bool {
	let res = slate
		.participant_data
		.clone()
		.into_iter()
		.filter(|v| !v.is_complete())
		.count();

	// We can finalize if the number of partial sigs is the same as the number of participants
	res == 0 && slate.participant_data.len() == slate.num_participants as usize
}

/// Finalize slate
pub fn finalize_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Final transaction can be built by anyone at this stage
	trace!("Slate to finalize is: {}", slate);
	// At this point, everyone adjusted their offset, so we update the offset on the tx
	slate.tx_or_err_mut()?.offset = slate.offset.clone();
	slate.finalize(&w.keychain(keychain_mask)?)?;

	Ok(())
}

/// Atomically locks the inputs and saves the changes of Context, TxLogEntry and OutputData.
/// Additionally, the transaction is saved in a file in case we signed it.
pub fn save_step<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	context: &mut Context,
	step_added_outputs: bool,
	is_signed: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!(
		"contract_utils::save_step => performing atomic update for slate_id: {}",
		slate.id
	);
	// Phase 1 - precompute the data needed for atomic update
	let parent_key_id = &context.parent_key_id;
	let current_height = w.w2n_client().get_chain_tip()?.0;
	// We are at step2 if we don't have context.log_id and we have signed the slate
	let is_step2 = !context.log_id.is_some() && is_signed;

	let mut tx_log_entry = {
		if !context.log_id.is_some() {
			// We create a new entry with log_id=0 and but replace it with the real id before committing
			create_tx_log_entry(slate, context.get_net_change(), parent_key_id.clone(), 0)?
		} else {
			w.get_tx_log_entry(parent_key_id.clone(), context.log_id.unwrap())?
				.unwrap()
		}
	};
	// Update TxLogEntry if we have signed the contract (we have data about the kernel)
	if is_signed {
		update_tx_log_entry(w, keychain_mask, &slate, &context, &mut tx_log_entry)?;
		// TODO: It's possible to store the transaction in a file while and the atomic commit below fails
		// In this case, we should revert to the previous stored tx to avoid having discrepancy
		w.store_tx(&format!("{}", slate.id), slate.tx_or_err()?)?;
	}
	// If we added outputs in this step, we have to create OutputData here because 'batch'
	// takes the mutable ref and we can no longer call calc_commit_for_cache for output
	let added_outputs = if !step_added_outputs {
		vec![]
	} else {
		let mut output_data_xs: Vec<OutputData> = vec![];
		// Create an OutputData entry for every created output
		for (key_id, _, amount) in context.get_outputs() {
			let commit = w.calc_commit_for_cache(keychain_mask, amount, &key_id)?;
			let output_data = OutputData {
				root_key_id: parent_key_id.clone(),
				key_id: key_id.clone(),
				mmr_index: None,
				n_child: key_id.to_path().last_path_index(),
				commit: commit,
				value: amount,
				status: OutputStatus::Unconfirmed,
				height: current_height,
				lock_height: 0,
				is_coinbase: false,
				tx_log_entry: None,
			};
			output_data_xs.push(output_data);
		}
		output_data_xs
	};

	// Phase 2 - atomically update Context, OutputData and TxLogEntry
	let mut batch = w.batch(keychain_mask)?;

	// Update TxLogEntry
	if !context.log_id.is_some() {
		// If we just created the TxLogEntry, we have to assign it an id
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		tx_log_entry.id = log_id;
		context.log_id = Some(log_id);
	}
	batch.save_tx_log_entry(tx_log_entry.clone(), &parent_key_id)?;
	// Create OutputData entries and lock inputs if we added outputs at this step
	if step_added_outputs {
		// Create an OutputData entry for every created output
		for mut output_data in added_outputs {
			output_data.tx_log_entry = context.log_id;
			batch.save(output_data)?;
		}
		// Lock inputs
		for id in context.get_inputs() {
			let mut coin = batch.get(&id.0, &id.1).unwrap();
			// At this point we already have context.log_id set
			coin.tx_log_entry = context.log_id;
			batch.lock_output(&mut coin)?;
		}
	}
	// Update context
	if is_signed && !is_step2 {
		// NOTE: We MUST forget the context when we sign. Ideally, these two would be atomic or perhaps
		// when we add_partial_signature we could swap the secret key with a temporary one just to be safe.
		batch.delete_private_context(slate.id.as_bytes())?;
	} else {
		batch.save_private_context(slate.id.as_bytes(), &context)?;
	}

	batch.commit()?;

	// TODO: Assert we don't have the context to avoid potentially leaking it! Also write tests around this.
	debug!("contract_utils::save_step => Atomic updated done");

	Ok(())
}

/// Computes fees contribution for a participant
pub fn my_fee_contribution(
	n_inputs: usize,
	n_outputs: usize,
	n_kernels: usize,
	num_participants: u8,
) -> Result<FeeFields, Error> {
	// Add our fee costs for our inputs and a single output
	let mut fee = tx_fee(n_inputs, n_outputs, 0);
	// Add out fee costs for kernel. We pay 1/num_participants of a kernel cost
	let kernel_cost = tx_fee(0, 0, n_kernels);
	// TODO: we slightly overpay. Make sure to cover all the cases
	let my_kernel_cost = (kernel_cost as f64 / (num_participants as f64)).ceil();
	fee += my_kernel_cost as u64;

	// Add my fee contribution to the slate total fee.
	// TODO: Does this break compatibility with existing slates?
	let my_fee_fields = FeeFields::new(0, fee)?;
	Ok(my_fee_fields)
}

/// Returns true if the slate has already been signed (in our local database). Even if the
/// result is false, it's still possible it was signed but we don't have the data about it locally.
pub fn check_already_signed<'a, T: ?Sized, C, K>(w: &mut T, slate_id: Uuid) -> bool
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// If we have a transaction log entry for that slatepack that has a kernel value, then
	// we have already signed this slate.
	let tx = w
		.tx_log_iter()
		.find(|t| t.tx_slate_id.is_some() && t.tx_slate_id.unwrap() == slate_id);
	tx.is_some() && tx.unwrap().kernel_excess.is_some()
}

/// Compares the setup args provided at call with those in the Context and checks whether they conflict.
/// This is relevant to see if there's any conflict in the arguments provided at step1 with step3.
pub fn verify_setup_consistency(
	ctx_setup_args: &ContractSetupArgsAPI,
	cur_setup_args: &ContractSetupArgsAPI,
) -> Result<(), Error> {
	// Compare net_change
	if ctx_setup_args.net_change.unwrap() != cur_setup_args.net_change.unwrap() {
		panic!(
			"Inconsistent net change. Ctx net_change:{}, Current net_change: {}",
			ctx_setup_args.net_change.unwrap(),
			cur_setup_args.net_change.unwrap()
		);
	}
	// Compare num_participants
	if ctx_setup_args.num_participants != cur_setup_args.num_participants {
		panic!(
			"Inconsistent num_participants. Ctx num_participants:{}, Current num_participants: {}",
			ctx_setup_args.num_participants, cur_setup_args.num_participants
		);
	}
	// TODO: Should we verify add_outputs?

	// Compare OutputSelectionArgs
	verify_selection_consistency(
		&ctx_setup_args.selection_args,
		&cur_setup_args.selection_args,
	)?;
	Ok(())
}

/// Get the parent_key_id for a given wallet instance and src_acct_name
pub fn parent_key_for<'a, T: ?Sized, C, K>(w: &mut T, src_acct_name: Option<&String>) -> Identifier
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// TODO: does it matter what api.set_active_account is set? also check LMDB set_parent_key_id etc. methods
	// - Does it matter what api.set_active_account is set? I think w.parent_key_id() already takes the active one
	//   but the verify_consistency may need to verify this or perhaps give a warning that active is different than
	//   the one that was set at the first setup phase.
	let parent_key_id = match src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.clone()).unwrap();
			match pm {
				Some(p) => p.path,
				// TODO: should we error if the path is not found?
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};
	parent_key_id
}

/// Helper to print slate transaction structure
pub fn print_tx(sl: &Slate, msg: String) {
	let sl_temp = sl.clone();
	debug!(
		"contract::print_tx => {} - has_tx: {}",
		msg,
		sl_temp.tx.is_some()
	);
	let final_tx = sl_temp.tx.unwrap().body;

	debug!(
		"contract::print_tx => {} - tx inputs:{}, outputs:{}, kernels:{}, offset_is_zero: {}",
		msg,
		final_tx.inputs().len(),
		final_tx.outputs().len(),
		final_tx.kernels().len(),
		sl_temp.offset.is_zero()
	);
}
