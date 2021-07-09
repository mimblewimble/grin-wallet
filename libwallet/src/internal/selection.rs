// Copyright 2021 The Grin Developers
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

//! Selection of inputs for building transactions

use rand::thread_rng;

use crate::address;
use crate::error::{Error, ErrorKind};
use crate::grin_core::core::{amount_to_hr_string, Output, OutputFeatures};
use crate::grin_core::libtx::{
	build,
	proof::{create_multisig, ProofBuild, ProofBuilder},
	tx_fee,
};
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen;
use crate::grin_util::{from_hex, ToHex};
use crate::internal::keys;
use crate::slate::{Slate, SlateState};
use crate::types::*;
use crate::util::OnionV3Address;
use std::collections::HashMap;
use std::convert::TryInto;

/// Initialize a transaction on the sender side, returns a corresponding
/// libwallet transaction slate with the appropriate inputs selected,
/// and saves the private wallet identifiers of our selected outputs
/// into our transaction context

pub fn build_send_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain: &K,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	fixed_fee: Option<u64>,
	parent_key_id: Identifier,
	multisig_key_id: Option<&Identifier>,
	use_test_nonce: bool,
	is_initiator: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (elems, inputs, change_amounts_derivations, fee) = select_send_tx(
		wallet,
		keychain_mask,
		slate.amount,
		current_height,
		minimum_confirmations,
		max_outputs,
		change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
		multisig_key_id,
		false,
	)?;

	if fixed_fee.map(|f| fee != f).unwrap_or(false) {
		return Err(ErrorKind::Fee("The initially selected fee is not sufficient".into()).into());
	}

	// Update the fee on the slate so we account for this when building the tx.
	slate.fee_fields = fee.try_into().unwrap();
	slate.add_transaction_elements(keychain, &ProofBuilder::new(keychain), elems)?;

	// Create our own private context
	let mut context = Context::new(
		keychain.secp(),
		&parent_key_id,
		use_test_nonce,
		is_initiator,
	);

	context.fee = Some(slate.fee_fields);
	context.amount = slate.amount;

	// Store our private identifiers for each input
	for input in inputs {
		context.add_input(&input.key_id, &input.mmr_index, input.value);
	}

	let mut commits: HashMap<Identifier, Option<String>> = HashMap::new();

	// Store change output(s) and cached commits
	for (change_amount, id, mmr_index) in &change_amounts_derivations {
		context.add_output(&id, &mmr_index, *change_amount);
		commits.insert(
			id.clone(),
			wallet.calc_commit_for_cache(keychain_mask, *change_amount, &id)?,
		);
	}

	Ok(context)
}

/// Locks all corresponding outputs in the context, creates
/// change outputs and tx log entry
pub fn lock_tx_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	current_height: u64,
	context: &Context,
	excess_override: Option<pedersen::Commitment>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut output_commits: HashMap<Identifier, (Option<String>, u64)> = HashMap::new();
	// Store cached commits before locking wallet
	let mut total_change = 0;
	for (id, _, change_amount) in &context.get_outputs() {
		output_commits.insert(
			id.clone(),
			(
				wallet.calc_commit_for_cache(keychain_mask, *change_amount, &id)?,
				*change_amount,
			),
		);
		total_change += change_amount;
	}

	debug!("Change amount is: {}", total_change);

	let keychain = wallet.keychain(keychain_mask)?;

	let tx_entry = {
		let lock_inputs = context.get_inputs();
		let slate_id = slate.id;
		let height = current_height;
		let parent_key_id = context.parent_key_id.clone();
		let mut batch = wallet.batch(keychain_mask)?;
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, log_id);
		t.tx_slate_id = Some(slate_id);
		let filename = format!("{}.grintx", slate_id);
		t.stored_tx = Some(filename);
		t.fee = context.fee;
		t.ttl_cutoff_height = match slate.ttl_cutoff_height {
			0 => None,
			n => Some(n),
		};

		if let Ok(e) = slate.calc_excess(keychain.secp()) {
			t.kernel_excess = Some(e)
		}
		if let Some(e) = excess_override {
			t.kernel_excess = Some(e)
		}
		t.kernel_lookup_min_height = Some(current_height);

		let mut amount_debited = 0;
		t.num_inputs = lock_inputs.len();
		for id in lock_inputs {
			let mut coin = batch.get(&id.0, &id.1).unwrap();
			coin.tx_log_entry = Some(log_id);
			amount_debited += coin.value;
			batch.lock_output(&mut coin)?;
		}

		t.amount_debited = amount_debited;

		// store extra payment proof info, if required
		if let Some(ref p) = slate.payment_proof {
			let sender_address_path = match context.payment_proof_derivation_index {
				Some(p) => p,
				None => {
					return Err(ErrorKind::PaymentProof(
						"Payment proof derivation index required".to_owned(),
					)
					.into());
				}
			};
			let sender_key = address::address_from_derivation_path(
				&keychain,
				&parent_key_id,
				sender_address_path,
			)?;
			let sender_address = OnionV3Address::from_private(&sender_key.0)?;
			t.payment_proof = Some(StoredProofInfo {
				receiver_address: p.receiver_address,
				receiver_signature: p.receiver_signature,
				sender_address: sender_address.to_ed25519()?,
				sender_address_path,
				sender_signature: None,
			});
		};

		// write the output representing our change
		for (id, _, _) in &context.get_outputs() {
			t.num_outputs += 1;
			let (commit, change_amount) = output_commits.get(&id).unwrap().clone();
			t.amount_credited += change_amount;
			batch.save(OutputData {
				root_key_id: parent_key_id.clone(),
				key_id: id.clone(),
				n_child: id.to_path().last_path_index(),
				commit: commit,
				mmr_index: None,
				value: change_amount,
				status: OutputStatus::Unconfirmed,
				height: height,
				lock_height: 0,
				is_coinbase: false,
				is_multisig: slate.is_multisig(),
				tx_log_entry: Some(log_id),
			})?;
		}
		batch.save_tx_log_entry(t.clone(), &parent_key_id)?;
		batch.commit()?;
		t
	};
	wallet.store_tx(
		&format!("{}", tx_entry.tx_slate_id.unwrap()),
		slate.tx_or_err()?,
	)?;
	Ok(())
}

/// Creates a new output in the wallet for the recipient,
/// returning the key of the fresh output
/// Also creates a new transaction containing the output
pub fn build_recipient_output<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	parent_key_id: Identifier,
	use_test_rng: bool,
	is_initiator: bool,
) -> Result<(Identifier, Context, TxLogEntry), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let is_multisig = slate
		.participant_data
		.iter()
		.fold(false, |t, d| t | d.part_commit.is_some());

	// Create a potential output for this transaction
	let key_id = match is_multisig {
		true => slate.create_multisig_id(),
		false => keys::next_available_key(wallet, keychain_mask).unwrap(),
	};
	let keychain = wallet.keychain(keychain_mask)?;
	let key_id_inner = key_id.clone();
	let amount = slate.amount;
	let height = current_height;

	let slate_id = slate.id;

	// Add blinding sum to our context
	let mut context = Context::new(keychain.secp(), &parent_key_id, use_test_rng, is_initiator);

	context.add_output(&key_id, &None, amount);
	context.amount = amount;
	context.fee = slate.fee_fields.as_opt();

	let (commit, output) = if is_multisig {
		let (_, public_nonce) = context.get_public_keys(keychain.secp());
		let data = slate
			.participant_data
			.iter()
			.find(|d| d.public_nonce != public_nonce)
			.ok_or(Error::from(ErrorKind::GenericError(
				"missing other participant data".into(),
			)))?;

		let oth_partial_commit = data.part_commit.ok_or(Error::from(ErrorKind::Commit(
			"missing partial commit".into(),
		)))?;

		// calculate the commit sum of the participants' partial commits
		let (partial_commit, commit_sum) = wallet.calc_multisig_commit_for_cache(
			keychain_mask,
			amount,
			&key_id_inner,
			&oth_partial_commit,
		)?;

		context.partial_commit = partial_commit;
		context.tau_one = Some(PublicKey::new());
		context.tau_two = Some(PublicKey::new());

		// create the common nonce: SecretKey(SHA3("multisig_common_nonce" || secNonce*pubNonce))
		let oth_public_nonce = &data.public_nonce;
		let common_nonce = context.create_common_nonce(keychain.secp(), oth_public_nonce)?;

		// calculate receiver's tau_one and tau_two public keys for the multisig bulletproof
		let _ = create_multisig(
			&keychain,
			&ProofBuilder::new(&keychain),
			amount,
			&key_id_inner,
			SwitchCommitmentType::Regular,
			&common_nonce,
			None,
			context.tau_one.as_mut(),
			context.tau_two.as_mut(),
			&[commit_sum.clone().unwrap()],
			1,
			None,
		)?;

		(
			Some(commit_sum.unwrap().0.to_vec().to_hex()),
			build::multisig_output(amount, key_id.clone(), oth_partial_commit.clone()),
		)
	} else {
		(
			wallet.calc_commit_for_cache(keychain_mask, amount, &key_id_inner)?,
			build::output(amount, key_id.clone()),
		)
	};

	slate.add_transaction_elements(&keychain, &ProofBuilder::new(&keychain), vec![output])?;

	let mut batch = wallet.batch(keychain_mask)?;
	let log_id = batch.next_tx_log_id(&parent_key_id)?;
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);
	t.tx_slate_id = Some(slate_id);
	t.amount_credited = amount;
	t.num_outputs = 1;
	t.ttl_cutoff_height = match slate.ttl_cutoff_height {
		0 => None,
		n => Some(n),
	};
	// when invoicing, this will be invalid
	if let Ok(e) = slate.calc_excess(keychain.secp()) {
		t.kernel_excess = Some(e)
	}
	t.kernel_lookup_min_height = Some(current_height);
	batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: key_id_inner.clone(),
		mmr_index: None,
		n_child: key_id_inner.to_path().last_path_index(),
		commit: commit,
		value: amount,
		status: OutputStatus::Unconfirmed,
		height: height,
		lock_height: 0,
		is_coinbase: false,
		is_multisig: slate.is_multisig(),
		tx_log_entry: Some(log_id),
	})?;
	batch.save_tx_log_entry(t.clone(), &parent_key_id)?;
	batch.commit()?;

	Ok((key_id, context, t))
}

/// Builds a transaction to send to someone from the HD seed associated with the
/// wallet and the amount to send. Handles reading through the wallet data file,
/// selecting outputs to spend and building the change.
pub fn select_send_tx<'a, T: ?Sized, C, K, B>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	multisig_key_id: Option<&Identifier>,
	include_inputs_in_sum: bool,
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<OutputData>,
		Vec<(u64, Identifier, Option<u64>)>, // change amounts and derivations
		u64,                                 // fee
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	B: ProofBuild,
{
	let (coins, _total, amount, fee) = select_coins_and_fee(
		wallet,
		amount,
		current_height,
		minimum_confirmations,
		max_outputs,
		change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
		multisig_key_id,
	)?;

	// build transaction skeleton with inputs and change
	let (parts, change_amounts_derivations) = inputs_and_change(
		&coins,
		wallet,
		keychain_mask,
		amount,
		fee,
		change_outputs,
		include_inputs_in_sum,
	)?;

	Ok((parts, coins, change_amounts_derivations, fee))
}

/// Select outputs and calculating fee.
pub fn select_coins_and_fee<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	multisig_key_id: Option<&Identifier>,
) -> Result<
	(
		Vec<OutputData>,
		u64, // total
		u64, // amount
		u64, // fee
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// select some spendable coins from the wallet
	let (max_outputs, mut coins) = select_coins(
		wallet,
		amount,
		current_height,
		minimum_confirmations,
		max_outputs,
		selection_strategy_is_use_all,
		parent_key_id,
		multisig_key_id,
	);

	// sender is responsible for setting the fee on the partial tx
	// recipient should double check the fee calculation and not blindly trust the
	// sender

	// First attempt to spend without change
	let mut fee = tx_fee(coins.len(), 1, 1);
	let mut total: u64 = coins.iter().map(|c| c.value).sum();
	let mut amount_with_fee = amount + fee;

	if total == 0 {
		return Err(ErrorKind::NotEnoughFunds {
			available: 0,
			available_disp: amount_to_hr_string(0, false),
			needed: amount_with_fee as u64,
			needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
		}
		.into());
	}

	// The amount with fee is more than the total values of our max outputs
	if total < amount_with_fee && coins.len() == max_outputs {
		return Err(ErrorKind::NotEnoughFunds {
			available: total,
			available_disp: amount_to_hr_string(total, false),
			needed: amount_with_fee as u64,
			needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
		}
		.into());
	}

	let num_outputs = change_outputs + 1;

	// We need to add a change address or amount with fee is more than total
	if total != amount_with_fee {
		fee = tx_fee(coins.len(), num_outputs, 1);
		amount_with_fee = amount + fee;

		// Here check if we have enough outputs for the amount including fee otherwise
		// look for other outputs and check again
		while total < amount_with_fee {
			// End the loop if we have selected all the outputs and still not enough funds
			if coins.len() == max_outputs {
				return Err(ErrorKind::NotEnoughFunds {
					available: total as u64,
					available_disp: amount_to_hr_string(total, false),
					needed: amount_with_fee as u64,
					needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
				}
				.into());
			}

			// select some spendable coins from the wallet
			coins = select_coins(
				wallet,
				amount_with_fee,
				current_height,
				minimum_confirmations,
				max_outputs,
				selection_strategy_is_use_all,
				parent_key_id,
				multisig_key_id,
			)
			.1;
			fee = tx_fee(coins.len(), num_outputs, 1);
			total = coins.iter().map(|c| c.value).sum();
			amount_with_fee = amount + fee;
		}
	}
	Ok((coins, total, amount, fee))
}

/// Selects inputs and change for a transaction
pub fn inputs_and_change<'a, T: ?Sized, C, K, B>(
	coins: &[OutputData],
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	fee: u64,
	num_change_outputs: usize,
	include_inputs_in_sum: bool,
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<(u64, Identifier, Option<u64>)>,
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	B: ProofBuild,
{
	let mut parts = vec![];

	// calculate the total across all inputs, and how much is left
	let total: u64 = coins.iter().map(|c| c.value).sum();

	// if we are spending 10,000 coins to send 1,000 then our change will be 9,000
	// if the fee is 80 then the recipient will receive 1000 and our change will be
	// 8,920
	let change = total - amount - fee;

	// build inputs using the appropriate derived key_ids
	if include_inputs_in_sum {
		for coin in coins {
			if coin.is_coinbase {
				parts.push(build::coinbase_input(coin.value, coin.key_id.clone()));
			} else {
				parts.push(build::input(coin.value, coin.key_id.clone()));
			}
		}
	}

	let mut change_amounts_derivations = vec![];

	if change == 0 {
		debug!("No change (sending exactly amount + fee), no change outputs to build");
	} else {
		debug!(
			"Building change outputs: total change: {} ({} outputs)",
			change, num_change_outputs
		);

		let part_change = change / num_change_outputs as u64;
		let remainder_change = change % part_change;

		for x in 0..num_change_outputs {
			// n-1 equal change_outputs and a final one accounting for any remainder
			let change_amount = if x == (num_change_outputs - 1) {
				part_change + remainder_change
			} else {
				part_change
			};

			let change_key = wallet.next_child(keychain_mask).unwrap();

			change_amounts_derivations.push((change_amount, change_key.clone(), None));
			parts.push(build::output(change_amount, change_key));
		}
	}

	Ok((parts, change_amounts_derivations))
}

/// Select spendable coins from a wallet.
/// Default strategy is to spend the maximum number of outputs (up to
/// max_outputs). Alternative strategy is to spend smallest outputs first
/// but only as many as necessary. When we introduce additional strategies
/// we should pass something other than a bool in.
/// TODO: Possibly move this into another trait to be owned by a wallet?

pub fn select_coins<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	select_all: bool,
	parent_key_id: &Identifier,
	multisig_key_id: Option<&Identifier>,
) -> (usize, Vec<OutputData>)
//    max_outputs_available, Outputs
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// first find all eligible outputs based on number of confirmations
	let key_id = multisig_key_id.unwrap_or(parent_key_id);
	let mut eligible = vec![];
	for out in wallet.iter() {
		if (out.root_key_id == *key_id || out.key_id == *key_id)
			&& out.eligible_to_spend(current_height, minimum_confirmations)
		{
			eligible.push(out.clone());
		}
	}

	let max_available = eligible.len();

	// sort eligible outputs by increasing value
	eligible.sort_by_key(|out| out.value);

	// use a sliding window to identify potential sets of possible outputs to spend
	// Case of amount > total amount of max_outputs(500):
	// The limit exists because by default, we always select as many inputs as
	// possible in a transaction, to reduce both the Output set and the fees.
	// But that only makes sense up to a point, hence the limit to avoid being too
	// greedy. But if max_outputs(500) is actually not enough to cover the whole
	// amount, the wallet should allow going over it to satisfy what the user
	// wants to send. So the wallet considers max_outputs more of a soft limit.
	if eligible.len() > max_outputs {
		for window in eligible.windows(max_outputs) {
			let windowed_eligibles = window.to_vec();
			if let Some(outputs) = select_from(amount, select_all, windowed_eligibles) {
				return (max_available, outputs);
			}
		}
		// Not exist in any window of which total amount >= amount.
		// Then take coins from the smallest one up to the total amount of selected
		// coins = the amount.
		if let Some(outputs) = select_from(amount, false, eligible.clone()) {
			debug!(
				"Extending maximum number of outputs. {} outputs selected.",
				outputs.len()
			);
			return (max_available, outputs);
		}
	} else if let Some(outputs) = select_from(amount, select_all, eligible.clone()) {
		return (max_available, outputs);
	}

	// we failed to find a suitable set of outputs to spend,
	// so return the largest amount we can so we can provide guidance on what is
	// possible
	eligible.reverse();
	(
		max_available,
		eligible.iter().take(max_outputs).cloned().collect(),
	)
}

fn select_from(amount: u64, select_all: bool, outputs: Vec<OutputData>) -> Option<Vec<OutputData>> {
	let total = outputs.iter().fold(0, |acc, x| acc + x.value);
	if total >= amount {
		if select_all {
			Some(outputs.to_vec())
		} else {
			let mut selected_amount = 0;
			Some(
				outputs
					.iter()
					.take_while(|out| {
						let res = selected_amount < amount;
						selected_amount += out.value;
						res
					})
					.cloned()
					.collect(),
			)
		}
	} else {
		None
	}
}

/// Repopulates output in the slate's tranacstion
/// with outputs from the stored context
/// change outputs and tx log entry
/// Remove the explicitly stored excess
pub fn repopulate_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
	update_fee: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// restore the original amount, fee
	slate.amount = context.amount;
	if update_fee {
		slate.fee_fields = context
			.fee
			.ok_or_else(|| ErrorKind::Fee("Missing fee fields".into()))?;
	}

	let keychain = wallet.keychain(keychain_mask)?;

	// restore my signature data
	slate.add_participant_info(&keychain, &context, None)?;

	let mut parts = vec![];
	for (id, _, value) in &context.get_inputs() {
		let input = wallet.iter().find(|out| out.key_id == *id);
		if let Some(i) = input {
			if i.is_coinbase {
				parts.push(build::coinbase_input(*value, i.key_id.clone()));
			} else if i.is_multisig {
				let commit_str = i.commit.ok_or(Error::from(ErrorKind::GenericError(
					"missing multisig output commitment".into(),
				)))?;
				let commit = pedersen::Commitment::from_hex(&commit_str)?;
				parts.push(build::multisig_input(*value, i.key_id.clone(), commit));
			} else {
				parts.push(build::input(*value, i.key_id.clone()));
			}
		}
	}
	for (id, _, value) in &context.get_outputs() {
		let output = wallet.iter().find(|out| out.key_id == *id);
		if let Some(i) = output {
			parts.push(build::output(*value, i.key_id.clone()));
		}
	}
	let _ = slate.add_transaction_elements(&keychain, &ProofBuilder::new(&keychain), parts)?;
	// restore the original offset
	slate.tx_or_err_mut()?.offset = slate.offset.clone();
	Ok(())
}

pub fn finalize_multisig_bulletproof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<Option<SecretKey>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = wallet.keychain(keychain_mask)?;
	let secp = keychain.secp();
	let (_, pub_nonce) = context.get_public_keys(secp);
	let oth_data = slate
		.participant_data
		.iter()
		.find(|d| d.public_nonce != pub_nonce)
		.ok_or(Error::from(ErrorKind::GenericError(
			"missing other participant data".into(),
		)))?;

	let common_nonce = context.create_common_nonce(secp, &oth_data.public_nonce)?;

	let key_id = slate.create_multisig_id();

	let amount = slate.amount;
	let out = wallet
		.iter()
		.find(|o| o.key_id == key_id)
		.ok_or(Error::from(ErrorKind::GenericError(
			"missing multisig output".into(),
		)))?;
	let commit_str = out
		.commit
		.as_ref()
		.ok_or(Error::from(ErrorKind::GenericError(
			"missing multisig output commit".into(),
		)))?;
	let commit_hex = from_hex(&commit_str)
		.map_err(|e| ErrorKind::GenericError(format!("invalid hex: {}", e)))?;
	let commit = pedersen::Commitment::from_vec(commit_hex);

	let is_initiator_final = context.tau_x.is_some();
	if !is_initiator_final {
		let tau_one = context.tau_one.ok_or(Error::from(ErrorKind::GenericError(
			"missing tau one multisig key".into(),
		)))?;
		let tau_two = context.tau_two.ok_or(Error::from(ErrorKind::GenericError(
			"missing tau two multisig key".into(),
		)))?;
		let oth_tau_one = oth_data.tau_one.ok_or(Error::from(ErrorKind::GenericError(
			"missing other tau one multisig key".into(),
		)))?;
		let oth_tau_two = oth_data.tau_two.ok_or(Error::from(ErrorKind::GenericError(
			"missing other tau two multisig key".into(),
		)))?;
		context.tau_one = Some(PublicKey::from_combination(
			secp,
			vec![&tau_one, &oth_tau_one],
		)?);
		context.tau_two = Some(PublicKey::from_combination(
			secp,
			vec![&tau_two, &oth_tau_two],
		)?);
		context.tau_x = Some(SecretKey::new(secp, &mut thread_rng()));
		let _ = create_multisig(
			&keychain,
			&ProofBuilder::new(&keychain),
			amount,
			&key_id,
			SwitchCommitmentType::Regular,
			&common_nonce,
			context.tau_x.as_mut(),
			context.tau_one.as_mut(),
			context.tau_two.as_mut(),
			&[commit],
			2,
			None,
		)?;
	}
	let mut tau_x_sum = context
		.tau_x
		.clone()
		.ok_or(Error::from(ErrorKind::GenericError(
			"missing local tau x".into(),
		)))?;
	// Save for receiver to add to the slate, can be ignored for initiator finalization
	let ret_tau_x = Some(tau_x_sum.clone());
	let oth_tau_x = oth_data
		.tau_x
		.as_ref()
		.ok_or(Error::from(ErrorKind::GenericError(
			"missing other tau x".into(),
		)))?;
	tau_x_sum.add_assign(secp, oth_tau_x)?;

	if is_initiator_final {
		let proof = create_multisig(
			&keychain,
			&ProofBuilder::new(&keychain),
			amount,
			&key_id,
			SwitchCommitmentType::Regular,
			&common_nonce,
			Some(&mut tau_x_sum),
			context.tau_one.as_mut(),
			context.tau_two.as_mut(),
			&[commit.clone()],
			0,
			None,
		)?
		.ok_or(Error::from(ErrorKind::GenericError(
			"error creating final multisig proof".into(),
		)))?;

		let output = Output::new(OutputFeatures::Multisig, commit.clone(), proof);
		output.verify_proof()?;

		// replace the multisig output's rangeproof with the finalized multisig proof
		let mut new_outs = vec![output];
		let old_outs: Vec<Output> = slate
			.tx_or_err()?
			.outputs()
			.iter()
			.filter(|o| o.identifier.commit != commit)
			.map(|o| o.clone())
			.collect();
		new_outs.extend_from_slice(&old_outs[..]);
		slate.tx_or_err_mut()?.body.outputs = new_outs;
	} else {
		context.tau_x = Some(tau_x_sum);
	}

	slate.state = SlateState::Multisig4;

	Ok(ret_tau_x)
}
