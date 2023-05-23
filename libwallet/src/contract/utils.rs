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

use crate::contract::selection::verify_selection_consistency;
use crate::contract::types::ContractSetupArgsAPI;
use crate::grin_core::libtx::tx_fee;
use crate::grin_keychain::{Identifier, Keychain};
use crate::grin_util::secp::key::SecretKey;
use crate::slate::Slate;
use crate::types::{Context, NodeClient, TxLogEntryType, WalletBackend};
use crate::util::OnionV3Address;
use crate::{address, Error, OutputData, OutputStatus, TxLogEntry};
use grin_core::core::FeeFields;
use uuid::Uuid;

use super::proofs::InvoiceProof;

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

	// If we're sending and there's payment proof info in the slate added by recipient, store as well
	if let Some(ref p) = slate.payment_proof {
		if tx_log_entry.amount_debited > 0 {
			let derivation_index = match context.payment_proof_derivation_index {
				Some(i) => i,
				None => 0,
			};
			let parent_key_id = wallet.parent_key_id();
			let sender_key =
				address::address_from_derivation_path(&keychain, &parent_key_id, derivation_index)?;
			let sender_address = OnionV3Address::from_private(&sender_key.0)?;

			let my_index = slate.find_index_matching_context(&keychain, context)?;
			tx_log_entry.payment_proof_2 = Some(
				InvoiceProof::from_slate(&slate, my_index, Some(sender_address.to_ed25519()?))?
					.stored_info,
			);
		}
	};

	Ok(())
}

/// Get net_change value. This is obtained either from the Context.net_change or the setup_args.net_change
pub fn get_net_change<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	// TODO: make this receive only slate.id instead of passing the whole slate
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
		Err(_) => debug!("contract::utils::get_net_change => context not found"),
	};

	// Fail if net_change was not passed to setup_args and was also not present in the context.
	// This means it has not been explicitly agreed on and we require the user to pass it.
	if expected_net_change.is_none() {
		return Err(Error::GenericError(
			"You did not agree on the expected net difference.".into(),
		)
		.into());
	}
	debug!(
		"contract::utils::get_net_change => expected_net_change: {}",
		expected_net_change.unwrap()
	);

	Ok(expected_net_change.unwrap())
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
		"contract::utils::save_step => performing atomic update for slate_id: {}",
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
		// when we call slate::sigadd_partial_signaturen we could swap the secret key with a temporary one just to be safe.
		// The reason we don't delete if we are at step2 is because in case we want to do safe cancel,
		// we need to know which inputs are in the context to know which input we have to double-spend.
		batch.delete_private_context(slate.id.as_bytes())?;
	} else {
		batch.save_private_context(slate.id.as_bytes(), &context)?;
	}

	batch.commit()?;

	// TODO: Assert we don't have the context to avoid potentially leaking it! Also write tests around this.
	debug!("contract::utils::save_step => Atomic updated done");

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

/// Returns an error if the slate has already been signed (in our local database). Even if the
/// result is Ok, it's still possible it was signed but we don't have the data about it locally.
pub fn verify_not_signed<'a, T: ?Sized, C, K>(w: &mut T, slate_id: Uuid) -> Result<(), Error>
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
	let already_signed = tx.is_some() && tx.unwrap().kernel_excess.is_some();
	if already_signed {
		debug!("contract::utils::verify_not_signed => The slate has already been signed.");
		return Err(Error::GenericError(
			format!("Slate with id:{} has already been signed.", slate_id).into(),
		)
		.into());
	}

	Ok(())
}

/// Compares the setup args provided at call with those in the Context and checks whether they conflict.
/// This is relevant to see if there's any conflict in the arguments provided at step1 with step3.
pub fn verify_setup_args_consistency(
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
	// TODO: verify that the parent_key_id is consistent, perhaps even with the active_account set?

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
