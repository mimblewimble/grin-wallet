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

//! Utilities to check the status of all the outputs we have stored in
//! the wallet storage and update them.

use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::error::Error;
use crate::grin_core::consensus::reward;
use crate::grin_core::core::{Output, TxKernel};
use crate::grin_core::global;
use crate::grin_core::libtx::proof::ProofBuilder;
use crate::grin_core::libtx::reward;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util as util;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::grin_util::static_secp_instance;
use crate::internal::keys;
use crate::types::{
	NodeClient, OutputData, OutputStatus, TxLogEntry, TxLogEntryType, WalletBackend, WalletInfo,
};
use crate::{BlockFees, CbData, OutputCommitMapping};

/// Retrieve all of the outputs (doesn't attempt to update from node)
pub fn retrieve_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	show_spent: bool,
	tx_id: Option<u32>,
	parent_key_id: Option<&Identifier>,
) -> Result<Vec<OutputCommitMapping>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// just read the wallet here, no need for a write lock
	let mut outputs = wallet
		.iter()
		.filter(|out| show_spent || out.status != OutputStatus::Spent)
		.collect::<Vec<_>>();

	// only include outputs with a given tx_id if provided
	if let Some(id) = tx_id {
		outputs = outputs
			.into_iter()
			.filter(|out| out.tx_log_entry == Some(id))
			.collect::<Vec<_>>();
	}

	if let Some(k) = parent_key_id {
		outputs = outputs
			.iter()
			.filter(|o| o.root_key_id == *k)
			.cloned()
			.collect()
	}

	outputs.sort_by_key(|out| out.n_child);
	let keychain = wallet.keychain(keychain_mask)?;

	let res = outputs
		.into_iter()
		.map(|output| {
			let commit = match output.commit.clone() {
				Some(c) => pedersen::Commitment::from_vec(util::from_hex(&c).unwrap()),
				None => keychain
					.commit(output.value, &output.key_id, SwitchCommitmentType::Regular)
					.unwrap(), // TODO: proper support for different switch commitment schemes
			};
			OutputCommitMapping { output, commit }
		})
		.collect();
	Ok(res)
}

/// Retrieve all of the transaction entries, or a particular entry
/// if `parent_key_id` is set, only return entries from that key
pub fn retrieve_txs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
	parent_key_id: Option<&Identifier>,
	outstanding_only: bool,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut txs: Vec<TxLogEntry> = wallet
		.tx_log_iter()
		.filter(|tx_entry| {
			let f_pk = match parent_key_id {
				Some(k) => tx_entry.parent_key_id == *k,
				None => true,
			};
			let f_tx_id = match tx_id {
				Some(i) => tx_entry.id == i,
				None => true,
			};
			let f_txs = match tx_slate_id {
				Some(t) => tx_entry.tx_slate_id == Some(t),
				None => true,
			};
			let f_outstanding = match outstanding_only {
				true => {
					!tx_entry.confirmed
						&& (tx_entry.tx_type == TxLogEntryType::TxReceived
							|| tx_entry.tx_type == TxLogEntryType::TxSent
							|| tx_entry.tx_type == TxLogEntryType::TxReverted)
				}
				false => true,
			};
			f_pk && f_tx_id && f_txs && f_outstanding
		})
		.collect();
	txs.sort_by_key(|tx| tx.creation_ts);
	Ok(txs)
}

/// Refreshes the outputs in a wallet with the latest information
/// from a node
pub fn refresh_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let height = wallet.w2n_client().get_chain_tip()?.0;
	refresh_output_state(wallet, keychain_mask, height, parent_key_id, update_all)?;
	Ok(())
}

/// build a local map of wallet outputs keyed by commit
/// and a list of outputs we want to query the node for
pub fn map_wallet_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<HashMap<pedersen::Commitment, (Identifier, Option<u64>, Option<u32>, bool)>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut wallet_outputs = HashMap::new();
	let keychain = wallet.keychain(keychain_mask)?;
	let unspents: Vec<OutputData> = wallet
		.iter()
		.filter(|x| x.root_key_id == *parent_key_id && x.status != OutputStatus::Spent)
		.collect();

	let tx_entries = retrieve_txs(wallet, None, None, Some(&parent_key_id), true)?;

	// Only select outputs that are actually involved in an outstanding transaction
	let unspents = match update_all {
		false => unspents
			.into_iter()
			.filter(|x| match x.tx_log_entry.as_ref() {
				Some(t) => tx_entries.iter().any(|te| te.id == *t),
				None => true,
			})
			.collect(),
		true => unspents,
	};

	for out in unspents {
		let commit = match out.commit.clone() {
			Some(c) => pedersen::Commitment::from_vec(util::from_hex(&c).unwrap()),
			None => keychain
				.commit(out.value, &out.key_id, SwitchCommitmentType::Regular)
				.unwrap(), // TODO: proper support for different switch commitment schemes
		};
		let val = (
			out.key_id.clone(),
			out.mmr_index,
			out.tx_log_entry,
			out.status == OutputStatus::Unspent,
		);
		wallet_outputs.insert(commit, val);
	}
	Ok(wallet_outputs)
}

/// Cancel transaction and associated outputs
pub fn cancel_tx_and_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	mut tx: TxLogEntry,
	outputs: Vec<OutputData>,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut batch = wallet.batch(keychain_mask)?;

	for mut o in outputs {
		// unlock locked outputs
		if o.status == OutputStatus::Unconfirmed || o.status == OutputStatus::Reverted {
			batch.delete(&o.key_id, &o.mmr_index)?;
		}
		if o.status == OutputStatus::Locked {
			o.status = OutputStatus::Unspent;
			batch.save(o)?;
		}
	}
	match tx.tx_type {
		TxLogEntryType::TxSent => tx.tx_type = TxLogEntryType::TxSentCancelled,
		TxLogEntryType::TxReceived | TxLogEntryType::TxReverted => {
			tx.tx_type = TxLogEntryType::TxReceivedCancelled
		}
		_ => {}
	}
	batch.save_tx_log_entry(tx, parent_key_id)?;
	batch.commit()?;
	Ok(())
}

/// Apply refreshed API output data to the wallet
pub fn apply_api_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_outputs: &HashMap<pedersen::Commitment, (Identifier, Option<u64>, Option<u32>, bool)>,
	api_outputs: &HashMap<pedersen::Commitment, (String, u64, u64)>,
	reverted_kernels: HashSet<u32>,
	height: u64,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// now for each commit, find the output in the wallet and the corresponding
	// api output (if it exists) and refresh it in-place in the wallet.
	// Note: minimizing the time we spend holding the wallet lock.
	{
		let last_confirmed_height = wallet.last_confirmed_height()?;
		// If the server height is less than our confirmed height, don't apply
		// these changes as the chain is syncing, incorrect or forking
		if height < last_confirmed_height {
			warn!(
				"Not updating outputs as the height of the node's chain \
				 is less than the last reported wallet update height."
			);
			warn!("Please wait for sync on node to complete or fork to resolve and try again.");
			return Ok(());
		}
		let mut batch = wallet.batch(keychain_mask)?;
		for (commit, (id, mmr_index, _, _)) in wallet_outputs.iter() {
			if let Ok(mut output) = batch.get(id, mmr_index) {
				match api_outputs.get(&commit) {
					Some(o) => {
						// if this is a coinbase tx being confirmed, it's recordable in tx log
						if output.is_coinbase && output.status == OutputStatus::Unconfirmed {
							let log_id = batch.next_tx_log_id(parent_key_id)?;
							let mut t = TxLogEntry::new(
								parent_key_id.clone(),
								TxLogEntryType::ConfirmedCoinbase,
								log_id,
							);
							t.confirmed = true;
							t.amount_credited = output.value;
							t.amount_debited = 0;
							t.num_outputs = 1;
							// calculate kernel excess for coinbase
							{
								let secp = static_secp_instance();
								let secp = secp.lock();
								let over_commit = secp.commit_value(output.value)?;
								let excess = secp.commit_sum(vec![*commit], vec![over_commit])?;
								t.kernel_excess = Some(excess);
								t.kernel_lookup_min_height = Some(height);
							}
							t.update_confirmation_ts();
							output.tx_log_entry = Some(log_id);
							batch.save_tx_log_entry(t, &parent_key_id)?;
						}
						// also mark the transaction in which this output is involved as confirmed
						// note that one involved input/output confirmation SHOULD be enough
						// to reliably confirm the tx
						if !output.is_coinbase
							&& (output.status == OutputStatus::Unconfirmed
								|| output.status == OutputStatus::Reverted)
						{
							let tx = batch.tx_log_iter().find(|t| {
								Some(t.id) == output.tx_log_entry
									&& t.parent_key_id == *parent_key_id
							});
							if let Some(mut t) = tx {
								if t.tx_type == TxLogEntryType::TxReverted {
									t.tx_type = TxLogEntryType::TxReceived;
									t.reverted_after = None;
								}
								t.update_confirmation_ts();
								t.confirmed = true;
								batch.save_tx_log_entry(t, &parent_key_id)?;
							}
						}
						output.height = o.1;
						output.mark_unspent();
					}
					None => {
						if !output.is_coinbase
							&& output
								.tx_log_entry
								.map(|i| reverted_kernels.contains(&i))
								.unwrap_or(false)
						{
							output.mark_reverted();
						} else {
							output.mark_spent();
						}
					}
				}
				batch.save(output)?;
			}
		}

		for mut tx in batch.tx_log_iter() {
			if reverted_kernels.contains(&tx.id) && tx.parent_key_id == *parent_key_id {
				tx.tx_type = TxLogEntryType::TxReverted;
				tx.reverted_after = tx.confirmation_ts.clone().and_then(|t| {
					let now = chrono::Utc::now();
					(now - t).to_std().ok()
				});
				tx.confirmed = false;
				batch.save_tx_log_entry(tx, &parent_key_id)?;
			}
		}

		{
			batch.save_last_confirmed_height(parent_key_id, height)?;
		}
		batch.commit()?;
	}
	Ok(())
}

/// Builds a single api query to retrieve the latest output data from the node.
/// So we can refresh the local wallet outputs.
fn refresh_output_state<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	height: u64,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("Refreshing wallet outputs");

	// build a local map of wallet outputs keyed by commit
	// and a list of outputs we want to query the node for
	let wallet_outputs = map_wallet_outputs(wallet, keychain_mask, parent_key_id, update_all)?;

	let wallet_output_keys = wallet_outputs.keys().copied().collect();

	let api_outputs = wallet
		.w2n_client()
		.get_outputs_from_node(wallet_output_keys)?;

	// For any disappeared output, check the on-chain status of the corresponding transaction kernel
	// If it is no longer present, the transaction was reverted due to a re-org
	let reverted_kernels =
		find_reverted_kernels(wallet, &wallet_outputs, &api_outputs, parent_key_id)?;

	apply_api_outputs(
		wallet,
		keychain_mask,
		&wallet_outputs,
		&api_outputs,
		reverted_kernels,
		height,
		parent_key_id,
	)?;
	clean_old_unconfirmed(wallet, keychain_mask, height)?;
	Ok(())
}

fn find_reverted_kernels<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	wallet_outputs: &HashMap<pedersen::Commitment, (Identifier, Option<u64>, Option<u32>, bool)>,
	api_outputs: &HashMap<pedersen::Commitment, (String, u64, u64)>,
	parent_key_id: &Identifier,
) -> Result<HashSet<u32>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut client = wallet.w2n_client().clone();
	let mut ids = HashSet::new();

	// Get transaction IDs for outputs that are no longer unspent
	for (commit, (_, _, tx_id, was_unspent)) in wallet_outputs {
		if let Some(tx_id) = *tx_id {
			if *was_unspent && !api_outputs.contains_key(commit) {
				ids.insert(tx_id);
			}
		}
	}

	// Get corresponding kernels
	let kernels = wallet
		.tx_log_iter()
		.filter(|t| {
			ids.contains(&t.id)
				&& t.parent_key_id == *parent_key_id
				&& t.tx_type == TxLogEntryType::TxReceived
		})
		.filter_map(|t| {
			t.kernel_excess
				.map(|e| (t.id, e, t.kernel_lookup_min_height))
		});

	// Check each of the kernels on-chain
	let mut reverted = HashSet::new();
	for (id, excess, min_height) in kernels {
		if client.get_kernel(&excess, min_height, None)?.is_none() {
			reverted.insert(id);
		}
	}

	Ok(reverted)
}

fn clean_old_unconfirmed<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	height: u64,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if height < 50 {
		return Ok(());
	}
	let mut ids_to_del = vec![];
	for out in wallet.iter() {
		if out.status == OutputStatus::Unconfirmed
			&& out.height > 0
			&& out.height < height - 50
			&& out.is_coinbase
		{
			ids_to_del.push(out.key_id.clone())
		}
	}
	let mut batch = wallet.batch(keychain_mask)?;
	for id in ids_to_del {
		batch.delete(&id, &None)?;
	}
	batch.commit()?;
	Ok(())
}

/// Retrieve summary info about the wallet
/// caller should refresh first if desired
pub fn retrieve_info<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	parent_key_id: &Identifier,
	minimum_confirmations: u64,
) -> Result<WalletInfo, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let current_height = wallet.last_confirmed_height()?;
	let outputs = wallet
		.iter()
		.filter(|out| out.root_key_id == *parent_key_id);

	let mut unspent_total = 0;
	let mut immature_total = 0;
	let mut awaiting_finalization_total = 0;
	let mut unconfirmed_total = 0;
	let mut locked_total = 0;
	let mut reverted_total = 0;

	for out in outputs {
		match out.status {
			OutputStatus::Unspent => {
				if out.is_coinbase && out.lock_height > current_height {
					immature_total += out.value;
				} else if out.num_confirmations(current_height) < minimum_confirmations {
					// Treat anything less than minimum confirmations as "unconfirmed".
					unconfirmed_total += out.value;
				} else {
					unspent_total += out.value;
				}
			}
			OutputStatus::Unconfirmed => {
				// We ignore unconfirmed coinbase outputs completely.
				if !out.is_coinbase {
					if minimum_confirmations == 0 {
						unconfirmed_total += out.value;
					} else {
						awaiting_finalization_total += out.value;
					}
				}
			}
			OutputStatus::Locked => {
				locked_total += out.value;
			}
			OutputStatus::Reverted => reverted_total += out.value,
			OutputStatus::Spent => {}
		}
	}

	Ok(WalletInfo {
		last_confirmed_height: current_height,
		minimum_confirmations,
		total: unspent_total + unconfirmed_total + immature_total,
		amount_awaiting_finalization: awaiting_finalization_total,
		amount_awaiting_confirmation: unconfirmed_total,
		amount_immature: immature_total,
		amount_locked: locked_total,
		amount_currently_spendable: unspent_total,
		amount_reverted: reverted_total,
	})
}

/// Build a coinbase output and insert into wallet
pub fn build_coinbase<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<CbData, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (out, kern, block_fees) = receive_coinbase(wallet, keychain_mask, block_fees, test_mode)?;

	Ok(CbData {
		output: out,
		kernel: kern,
		key_id: block_fees.key_id,
	})
}

//TODO: Split up the output creation and the wallet insertion
/// Build a coinbase output and the corresponding kernel
pub fn receive_coinbase<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<(Output, TxKernel, BlockFees), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let height = block_fees.height;
	let lock_height = height + global::coinbase_maturity();
	let key_id = block_fees.key_id();
	let parent_key_id = wallet.parent_key_id();

	let key_id = match key_id {
		Some(key_id) => match keys::retrieve_existing_key(wallet, key_id, None) {
			Ok(k) => k.0,
			Err(_) => keys::next_available_key(wallet, keychain_mask)?,
		},
		None => keys::next_available_key(wallet, keychain_mask)?,
	};

	{
		// Now acquire the wallet lock and write the new output.
		let amount = reward(block_fees.fees);
		let commit = wallet.calc_commit_for_cache(keychain_mask, amount, &key_id)?;
		let mut batch = wallet.batch(keychain_mask)?;
		batch.save(OutputData {
			root_key_id: parent_key_id,
			key_id: key_id.clone(),
			n_child: key_id.to_path().last_path_index(),
			mmr_index: None,
			commit: commit,
			value: amount,
			status: OutputStatus::Unconfirmed,
			height: height,
			lock_height: lock_height,
			is_coinbase: true,
			tx_log_entry: None,
		})?;
		batch.commit()?;
	}

	debug!(
		"receive_coinbase: built candidate output - {:?}, {}",
		key_id.clone(),
		key_id,
	);

	let mut block_fees = block_fees.clone();
	block_fees.key_id = Some(key_id.clone());

	debug!("receive_coinbase: {:?}", block_fees);

	let keychain = wallet.keychain(keychain_mask)?;
	let (out, kern) = reward::output(
		&keychain,
		&ProofBuilder::new(&keychain),
		&key_id,
		block_fees.fees,
		test_mode,
	)?;
	Ok((out, kern, block_fees))
}
