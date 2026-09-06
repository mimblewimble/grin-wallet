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

use crate::backend::WalletBackend;
use crate::contract::selection::verify_selection_consistency;
use crate::contract::types::ContractSetupArgsAPI;
use crate::grin_core::libtx::tx_fee;
use crate::grin_keychain::{Identifier, Keychain};
use crate::grin_util::secp::key::SecretKey;
use crate::slate::{PaymentProofType, Slate};
use crate::types::{Context, NodeClient, StoredProofInfo, TxLogEntryType};
use crate::util::OnionV3Address;
use crate::{address, Error, OutputData, OutputStatus, TxLogEntry};
use grin_core::core::{FeeFields, Transaction};
use uuid::Uuid;

/// Creates an initial TxLogEntry without input/output or kernel information
pub fn create_tx_log_entry(
	slate: &Slate,
	net_change: i64,
	parent_key_id: Identifier,
	log_id: u32,
) -> Result<TxLogEntry, Error> {
	let log_type = if slate.num_participants == 1 {
		TxLogEntryType::TxSelfSpend
	} else {
		if net_change > 0 {
			TxLogEntryType::TxReceived
		} else {
			TxLogEntryType::TxSent
		}
	};
	let mut t = TxLogEntry::new(parent_key_id.clone(), log_type, log_id);
	// stored_tx is set in save_step, once we have signed and the transaction is written.

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

/// Update TxLogEntry with data from the sign step
/// `participant_index` is our entry in `slate.participant_data`
pub fn update_tx_log_entry<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain: &K,
	slate: &Slate,
	context: &Context,
	participant_index: usize,
	tx_log_entry: &mut TxLogEntry,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	// This is expected to be called when we are signing the contract and have already contributed inputs & outputs
	let parent_key_id = context.parent_key_id.clone();
	let current_height = wallet.w2n_client().get_chain_tip()?.0;
	// We have already contributed inputs and outputs so we know how much of each we contribute
	tx_log_entry.num_outputs = context.output_ids.len();
	tx_log_entry.num_inputs = context.input_ids.len();
	tx_log_entry.fee = context.fee;
	// Set kernel information
	tx_log_entry.kernel_excess = Some(slate.calc_excess(keychain.secp())?);
	tx_log_entry.kernel_lookup_min_height = Some(current_height);

	// If we're sending and there's payment proof info in the slate added by recipient, store as well
	if let Some(ref p) = slate.payment_proof {
		if tx_log_entry.amount_debited > 0 {
			let timestamp = p
				.timestamp
				.ok_or_else(|| Error::PaymentProof("Missing proof timestamp".to_string()))?;
			// note we only use a single path for now
			let sender_address_path = 0u32;
			let sender_key = address::address_from_derivation_path(
				keychain,
				&parent_key_id,
				sender_address_path,
			)?;
			let sender_address = OnionV3Address::from_private(&sender_key.0)?;

			// We're looking for the OTHER party here, the recipient. The 'xor 1' pairing
			// only holds for a two-party slate, so check that before indexing: a slate
			// with a shorter participant list would otherwise panic here.
			if slate.participant_data.len() != 2 {
				return Err(Error::GenericError(format!(
					"Expected 2 participants for a payment proof, found {}",
					slate.participant_data.len()
				)));
			}
			let sender = slate
				.participant_data
				.get(participant_index)
				.ok_or(Error::ContextToIndex)?;
			let recipient = slate
				.participant_data
				.get(participant_index ^ 1)
				.ok_or(Error::ContextToIndex)?;
			let sender_public_nonce = if p.proof_type == PaymentProofType::SenderNonce {
				Some(context.sender_public_nonce.ok_or_else(|| {
					Error::PaymentProofValidation("Missing sender nonce context".into())
				})?)
			} else {
				None
			};

			tx_log_entry.payment_proof = Some(StoredProofInfo {
				receiver_address: p.receiver_address,
				receiver_signature: p.promise_signature,
				sender_address: sender_address.to_ed25519()?,
				sender_address_path,
				sender_signature: None,
				// Filled as separate steps for now; could be merged into a general case
				// once we know which nonces here belong to the recipient.
				proof_type: Some(p.proof_type.as_u8()),
				receiver_public_nonce: Some(recipient.public_nonce),
				receiver_public_excess: Some(recipient.public_blind_excess),
				timestamp: Some(timestamp),
				memo: p.memo.clone(),
				promise_signature: p.promise_signature,
				sender_part_sig: sender.part_sig,
				sender_public_nonce,
			});
		}
	}

	Ok(())
}

/// Get net_change value. This is obtained either from the Context.net_change or the setup_args.net_change
pub fn get_net_change(
	context: Option<&Context>,
	setup_args_net_change: Option<i64>,
) -> Result<i64, Error> {
	let mut expected_net_change: Option<i64> = setup_args_net_change;
	if let Some(context) = context {
		debug!("contract::sign => context found");
		// We have a context so we must have agreed on a certain net_change value in Context.net_change.
		// If we have both Context.net_change and setup_args.net_change, then they must be equal.
		let ctx_net_change = context.get_net_change()?;
		match expected_net_change {
			Some(args_net_change) => {
				if ctx_net_change != args_net_change {
					return Err(Error::GenericError(format!(
						"Expected net change mismatch! Context.net_change: {}, setup_args.net_change: {}",
						ctx_net_change, args_net_change
					)));
				}
			}
			None => (),
		}
		expected_net_change = Some(ctx_net_change);
	} else {
		debug!("contract::utils::get_net_change => context not found")
	}

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

/// Lock inputs and store the Context, TxLogEntry and OutputData atomically
/// Consumes the context and derives the signed state from our participant data
/// Signed transactions are written outside the database batch
pub fn save_step<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	mut context: Context,
	step_added_outputs: bool,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	debug!(
		"contract::utils::save_step => performing atomic update for slate_id: {}",
		slate.id
	);
	// Phase 1 - precompute the data needed for atomic update
	let parent_key_id = &context.parent_key_id;
	let keychain = w.keychain(keychain_mask)?;
	let participant_index = slate.find_index_matching_context(&keychain, &context)?;
	let is_signed = slate.participant_data[participant_index].is_complete();
	if is_signed {
		// Verify part_sig before using it as signed state
		slate.verify_part_sigs(keychain.secp())?;
	}
	let current_height = w.w2n_client().get_chain_tip()?.0;
	// We are at step2 if we don't have context.log_id and we have signed the slate
	let is_step2 = context.log_id.is_none() && is_signed;

	let mut tx_log_entry = {
		if context.log_id.is_none() {
			// We create a new entry with log_id=0 and but replace it with the real id before committing
			create_tx_log_entry(slate, context.get_net_change()?, parent_key_id.clone(), 0)?
		} else {
			let log_id = context.log_id.unwrap();
			w.get_tx_log_entry_by_id(parent_key_id.clone(), log_id)?
				.ok_or_else(|| Error::NotFoundErr(format!("Transaction log entry {}", log_id)))?
		}
	};

	// Update TxLogEntry if we have signed the contract (we have data about the kernel)
	if is_signed {
		update_tx_log_entry(
			w,
			&keychain,
			slate,
			&context,
			participant_index,
			&mut tx_log_entry,
		)?;
		// Record where the transaction is stored, as internal::selection does for a
		// standard send. store_tx below writes it under this name, and 'txs' reads the
		// field to report whether the transaction data is held.
		tx_log_entry.stored_tx = Some(format!("{}.grintx", slate.id));
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
	if context.log_id.is_none() {
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
			let mut coin = batch.get(&id.0, &id.1)?;
			// At this point we already have context.log_id set
			coin.tx_log_entry = context.log_id;
			batch.lock_output(&mut coin)?;
		}
	}

	// Update context
	if is_signed && !is_step2 {
		// NOTE: We MUST forget the context when we sign. Ideally, these two would be atomic or perhaps
		// when we call slate::sigadd_partial_signaturen we could swap the secret key with a temporary one just to be safe.
		// Keep the step2 context for contract view
		batch.delete_private_context(slate.id.as_bytes())?;
	} else {
		batch.save_private_context(slate.id.as_bytes(), &context)?;
	}

	batch.commit()?;

	// Confirm sec_key/sec_nonce are gone after signing, except for step2
	if is_signed && !is_step2 {
		match w.get_private_context(keychain_mask, slate.id.as_bytes()) {
			Err(Error::NotFoundErr(_)) => {}
			Err(e) => return Err(e),
			Ok(_) => {
				return Err(Error::GenericError(
					"signing context was not removed after signing".into(),
				));
			}
		}
	}

	// Store the signed transaction only after the wallet-state batch has committed (and
	// the signing context is confirmed gone), so a DB failure can't leave the stored tx
	// out of sync with wallet state. Matches the core convention (internal::selection).
	//
	// store_tx writes a file outside LMDB, so this cannot be part of the batch above and
	// a window remains: the write can fail with the tx log entry and the input locks
	// already committed. Making it atomic would mean holding stored transactions in the
	// database, which is how every transaction in the wallet is kept, not just contracts.
	// Until then the way out is to cancel the transaction, which releases the inputs
	// without reading the stored tx. Nothing has been broadcast at this point: the error
	// returns to the caller before it posts. Covered by
	// wallet_contract_self_spend_cancel_missing_stored_tx.
	if is_signed {
		w.store_tx(&format!("{}", slate.id), slate.tx_or_err()?)?;
	}
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
	fee_contribution(n_inputs, n_outputs, n_kernels, num_participants, None)
}

pub(super) fn fee_contribution(
	n_inputs: usize,
	n_outputs: usize,
	n_kernels: usize,
	num_participants: u8,
	fee_rate: Option<u32>,
) -> Result<FeeFields, Error> {
	verify_num_participants(num_participants)?;
	verify_fee_rate(fee_rate)?;
	let fee_for = |inputs: usize, outputs: usize, kernels: usize| match fee_rate {
		Some(rate) => Transaction::weight_by_iok(inputs as u64, outputs as u64, kernels as u64)
			.checked_mul(u64::from(rate))
			.ok_or_else(|| Error::GenericError("Contract fee overflow".to_string())),
		None => Ok(tx_fee(inputs, outputs, kernels)),
	};
	// Add our fee costs for our inputs and a single output
	let mut fee = fee_for(n_inputs, n_outputs, 0)?;
	// Add out fee costs for kernel. We pay 1/num_participants of a kernel cost
	let kernel_cost = fee_for(0, 0, n_kernels)?;
	// Round each participant's kernel share up, so the participants together never underpay;
	// the overpay is bounded to under one fee unit per participant.
	let my_kernel_cost = kernel_cost.div_ceil(u64::from(num_participants));
	fee = fee
		.checked_add(my_kernel_cost)
		.ok_or_else(|| Error::GenericError("Contract fee overflow".to_string()))?;

	// Add my fee contribution to the slate total fee. Uses the standard FeeFields
	// encoding; contracts rely on every participant applying the same
	// 1/num_participants split so the contributions together cover the kernel cost.
	let my_fee_fields = FeeFields::new(0, fee)?;
	Ok(my_fee_fields)
}

/// Contracts need at least one participant for fee splitting
/// More than two remain disabled because of the known multi-party attack
pub(super) fn verify_num_participants(num_participants: u8) -> Result<(), Error> {
	if !(1..=2).contains(&num_participants) {
		return Err(Error::GenericError(format!(
			"Unsupported num_participants: {} (expected 1 or 2)",
			num_participants
		)));
	}
	Ok(())
}

pub(super) fn verify_fee_rate(fee_rate: Option<u32>) -> Result<(), Error> {
	if fee_rate == Some(0) {
		return Err(Error::GenericError(
			"Contract fee rate must be at least 1".to_string(),
		));
	}
	Ok(())
}

/// Ensure the slate still carries the stored contract deadline
pub(super) fn verify_ttl(expected: Option<u64>, slate: &Slate) -> Result<(), Error> {
	let expected = expected.unwrap_or(0);
	if expected != slate.ttl_cutoff_height {
		return Err(Error::GenericError(format!(
			"Contract TTL changed from {} to {}",
			expected, slate.ttl_cutoff_height
		)));
	}
	Ok(())
}

/// Whether a transaction log entry shows that this wallet signed the slate.
pub(super) fn is_signed_tx(tx: &TxLogEntry, slate_id: Uuid) -> bool {
	tx.tx_slate_id == Some(slate_id) && tx.kernel_excess.is_some()
}

/// Returns an error if the slate has already been signed (in our local database). Even if the
/// result is Ok, it's still possible it was signed but we don't have the data about it locally.
pub fn verify_not_signed<C, K>(w: &mut WalletBackend<C, K>, slate_id: Uuid) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	// If we have a transaction log entry for that slatepack that has a kernel value, then
	// we have already signed this slate.
	for tx in w.tx_log_iter()? {
		let tx = tx?;
		if is_signed_tx(&tx, slate_id) {
			debug!("contract::utils::verify_not_signed => The slate has already been signed.");
			return Err(Error::GenericError(format!(
				"Slate with id:{} has already been signed.",
				slate_id
			)));
		}
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
		return Err(Error::GenericError(format!(
			"Inconsistent net change. Ctx net_change:{}, Current net_change: {}",
			ctx_setup_args.net_change.unwrap(),
			cur_setup_args.net_change.unwrap()
		)));
	}
	// Compare num_participants
	if ctx_setup_args.num_participants != cur_setup_args.num_participants {
		return Err(Error::GenericError(format!(
			"Inconsistent num_participants. Ctx num_participants:{}, Current num_participants: {}",
			ctx_setup_args.num_participants, cur_setup_args.num_participants
		)));
	}
	if let Some(fee_rate) = cur_setup_args.fee_rate {
		if Some(fee_rate) != ctx_setup_args.fee_rate {
			let setup = ctx_setup_args
				.fee_rate
				.map(|rate| rate.to_string())
				.unwrap_or_else(|| "default".to_string());
			return Err(Error::GenericError(format!(
				"Can't change fee rate after contract setup. setup:{}, current:{}",
				setup, fee_rate
			)));
		}
	}
	// add_outputs is intentionally forced true at the sign step (late lock), so it is not
	// part of this consistency check. parent_key_id is taken from the stored Context, so
	// later steps always derive under the contract's account regardless of the active one.

	// Compare OutputSelectionArgs
	verify_selection_consistency(
		&ctx_setup_args.selection_args,
		&cur_setup_args.selection_args,
	)?;
	Ok(())
}

/// Get the parent_key_id for a given wallet instance and src_acct_name.
/// Errors on an unknown account name rather than silently falling back to the
/// active account.
pub fn parent_key_for<C, K>(
	w: &mut WalletBackend<C, K>,
	src_acct_name: Option<&String>,
) -> Result<Identifier, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = match src_acct_name {
		Some(d) => match w.get_acct_path(d.clone())? {
			Some(p) => p.path,
			None => return Err(Error::UnknownAccountLabel(d.clone())),
		},
		None => w.parent_key_id(),
	};
	Ok(parent_key_id)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fee_contribution_kernel_split() {
		let (n_inputs, n_outputs, n_kernels) = (1, 1, 1);
		let base = tx_fee(n_inputs, n_outputs, 0);
		let kernel_cost = tx_fee(0, 0, n_kernels);

		// A single participant (self-spend) pays the whole kernel cost.
		let solo = my_fee_contribution(n_inputs, n_outputs, n_kernels, 1)
			.unwrap()
			.fee();
		assert_eq!(solo, base + kernel_cost);

		// Two participants each pay ceil(kernel_cost / 2) ...
		let half = my_fee_contribution(n_inputs, n_outputs, n_kernels, 2)
			.unwrap()
			.fee();
		let my_share = kernel_cost.div_ceil(2);
		assert_eq!(half, base + my_share);
		// ... and applying the same split, the participants together cover the kernel cost.
		assert!(2 * my_share >= kernel_cost);
	}

	#[test]
	fn custom_fee_rate() {
		let rate = 2;
		let fee = fee_contribution(1, 1, 1, 2, Some(rate)).unwrap();
		let base = Transaction::weight_by_iok(1, 1, 0) * u64::from(rate);
		let kernel = Transaction::weight_by_iok(0, 0, 1) * u64::from(rate);
		assert_eq!(fee.fee(), base + kernel.div_ceil(2));
		assert!(fee_contribution(1, 1, 1, 2, Some(0)).is_err());
	}

	#[test]
	fn fee_rate_consistency() {
		let setup = ContractSetupArgsAPI {
			net_change: Some(-1),
			fee_rate: Some(2),
			..Default::default()
		};
		assert!(verify_setup_args_consistency(&setup, &setup).is_ok());
		assert!(verify_setup_args_consistency(
			&setup,
			&ContractSetupArgsAPI {
				net_change: Some(-1),
				..Default::default()
			}
		)
		.is_ok());
		let err = verify_setup_args_consistency(
			&setup,
			&ContractSetupArgsAPI {
				net_change: Some(-1),
				fee_rate: Some(3),
				..Default::default()
			},
		)
		.unwrap_err();
		assert!(matches!(
			err,
			Error::GenericError(ref msg)
				if msg == "Can't change fee rate after contract setup. setup:2, current:3"
		));
	}

	#[test]
	fn participant_count() {
		assert!(verify_num_participants(1).is_ok());
		assert!(verify_num_participants(2).is_ok());
		for count in [0, 3] {
			let err = verify_num_participants(count).unwrap_err();
			assert!(matches!(
				err,
				Error::GenericError(ref msg)
					if msg == &format!(
						"Unsupported num_participants: {} (expected 1 or 2)",
						count
					)
			));
			assert!(my_fee_contribution(1, 1, 1, count).is_err());
		}
	}
}
