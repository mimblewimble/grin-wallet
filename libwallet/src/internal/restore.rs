// Copyright 2019 The Grin Developers
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
//! Functions to restore a wallet's outputs from just the master seed

use crate::grin_core::consensus::{valid_header_version, WEEK_HEIGHT};
use crate::grin_core::core::HeaderVersion;
use crate::grin_core::global;
use crate::grin_core::libtx::proof;
use crate::grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::internal::{keys, updater};
use crate::types::*;
use crate::{Error, OutputCommitMapping};
use std::collections::HashMap;
use std::time::Instant;

/// Utility struct for return values from below
#[derive(Clone)]
struct OutputResult {
	///
	pub commit: pedersen::Commitment,
	///
	pub key_id: Identifier,
	///
	pub n_child: u32,
	///
	pub mmr_index: u64,
	///
	pub value: u64,
	///
	pub height: u64,
	///
	pub lock_height: u64,
	///
	pub is_coinbase: bool,
}

#[derive(Debug, Clone)]
/// Collect stats in case we want to just output a single tx log entry
/// for restored non-coinbase outputs
struct RestoredTxStats {
	///
	pub log_id: u32,
	///
	pub amount_credited: u64,
	///
	pub num_outputs: usize,
}

fn identify_utxo_outputs<'a, T, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
) -> Result<Vec<OutputResult>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut wallet_outputs: Vec<OutputResult> = Vec::new();

	warn!(
		"Scanning {} outputs in the current Grin utxo set",
		outputs.len(),
	);

	let keychain = wallet.keychain(keychain_mask)?;
	let legacy_builder = proof::LegacyProofBuilder::new(&keychain);
	let builder = proof::ProofBuilder::new(&keychain);
	let legacy_version = HeaderVersion(1);

	for output in outputs.iter() {
		let (commit, proof, is_coinbase, height, mmr_index) = output;
		// attempt to unwind message from the RP and get a value
		// will fail if it's not ours
		let info = {
			// Before HF+2wk, try legacy rewind first
			let info_legacy =
				if valid_header_version(height.saturating_sub(2 * WEEK_HEIGHT), legacy_version) {
					proof::rewind(keychain.secp(), &legacy_builder, *commit, None, *proof)?
				} else {
					None
				};

			// If legacy didn't work, try new rewind
			if info_legacy.is_none() {
				proof::rewind(keychain.secp(), &builder, *commit, None, *proof)?
			} else {
				info_legacy
			}
		};

		let (amount, key_id, switch) = match info {
			Some(i) => i,
			None => {
				continue;
			}
		};

		let lock_height = if *is_coinbase {
			*height + global::coinbase_maturity()
		} else {
			*height
		};

		info!(
			"Output found: {:?}, amount: {:?}, key_id: {:?}, mmr_index: {},",
			commit, amount, key_id, mmr_index,
		);

		if switch != SwitchCommitmentType::Regular {
			warn!("Unexpected switch commitment type {:?}", switch);
		}

		wallet_outputs.push(OutputResult {
			commit: *commit,
			key_id: key_id.clone(),
			n_child: key_id.to_path().last_path_index(),
			value: amount,
			height: *height,
			lock_height: lock_height,
			is_coinbase: *is_coinbase,
			mmr_index: *mmr_index,
		});
	}
	Ok(wallet_outputs)
}

fn collect_chain_outputs<'a, T, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
) -> Result<Vec<OutputResult>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let batch_size = 1000;
	let mut start_index = 1;
	let mut result_vec: Vec<OutputResult> = vec![];
	loop {
		let (highest_index, last_retrieved_index, outputs) = wallet
			.w2n_client()
			.get_outputs_by_pmmr_index(start_index, batch_size)?;
		warn!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);

		result_vec.append(&mut identify_utxo_outputs(
			wallet,
			keychain_mask,
			outputs.clone(),
		)?);

		if highest_index == last_retrieved_index {
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	Ok(result_vec)
}

///
fn restore_missing_output<'a, T, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	output: OutputResult,
	found_parents: &mut HashMap<Identifier, u32>,
	tx_stats: &mut Option<&mut HashMap<Identifier, RestoredTxStats>>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let commit = wallet.calc_commit_for_cache(keychain_mask, output.value, &output.key_id)?;
	let mut batch = wallet.batch(keychain_mask)?;

	let parent_key_id = output.key_id.parent_path();
	if !found_parents.contains_key(&parent_key_id) {
		found_parents.insert(parent_key_id.clone(), 0);
		if let Some(ref mut s) = tx_stats {
			s.insert(
				parent_key_id.clone(),
				RestoredTxStats {
					log_id: batch.next_tx_log_id(&parent_key_id)?,
					amount_credited: 0,
					num_outputs: 0,
				},
			);
		}
	}

	let log_id = if tx_stats.is_none() || output.is_coinbase {
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let entry_type = match output.is_coinbase {
			true => TxLogEntryType::ConfirmedCoinbase,
			false => TxLogEntryType::TxReceived,
		};
		let mut t = TxLogEntry::new(parent_key_id.clone(), entry_type, log_id);
		t.confirmed = true;
		t.amount_credited = output.value;
		t.num_outputs = 1;
		t.update_confirmation_ts();
		batch.save_tx_log_entry(t, &parent_key_id)?;
		log_id
	} else {
		if let Some(ref mut s) = tx_stats {
			let ts = s.get(&parent_key_id).unwrap().clone();
			s.insert(
				parent_key_id.clone(),
				RestoredTxStats {
					log_id: ts.log_id,
					amount_credited: ts.amount_credited + output.value,
					num_outputs: ts.num_outputs + 1,
				},
			);
			ts.log_id
		} else {
			0
		}
	};

	let _ = batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output.key_id,
		n_child: output.n_child,
		mmr_index: Some(output.mmr_index),
		commit: commit,
		value: output.value,
		status: OutputStatus::Unspent,
		height: output.height,
		lock_height: output.lock_height,
		is_coinbase: output.is_coinbase,
		tx_log_entry: Some(log_id),
	});

	let max_child_index = found_parents.get(&parent_key_id).unwrap().clone();
	if output.n_child >= max_child_index {
		found_parents.insert(parent_key_id.clone(), output.n_child);
	}

	batch.commit()?;
	Ok(())
}

///
fn cancel_tx_log_entry<'a, T, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	output: &OutputData,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = output.key_id.parent_path();
	let updated_tx_entry = if output.tx_log_entry.is_some() {
		let entries = updater::retrieve_txs(
			wallet,
			output.tx_log_entry.clone(),
			None,
			Some(&parent_key_id),
			false,
		)?;
		if entries.len() > 0 {
			let mut entry = entries[0].clone();
			match entry.tx_type {
				TxLogEntryType::TxSent => entry.tx_type = TxLogEntryType::TxSentCancelled,
				TxLogEntryType::TxReceived => entry.tx_type = TxLogEntryType::TxReceivedCancelled,
				_ => {}
			}
			Some(entry)
		} else {
			None
		}
	} else {
		None
	};
	let mut batch = wallet.batch(keychain_mask)?;
	if let Some(t) = updated_tx_entry {
		batch.save_tx_log_entry(t, &parent_key_id)?;
	}
	batch.commit()?;
	Ok(())
}

/// Check / repair wallet contents
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn check_repair<'a, T, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	delete_unconfirmed: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// First, get a definitive list of outputs we own from the chain
	warn!("Starting wallet check.");
	let chain_outs = collect_chain_outputs(wallet, keychain_mask)?;
	warn!(
		"Identified {} wallet_outputs as belonging to this wallet",
		chain_outs.len(),
	);

	// Now, get all outputs owned by this wallet (regardless of account)
	let wallet_outputs = {
		let res = updater::retrieve_outputs(&mut *wallet, keychain_mask, true, None, None)?;
		res
	};

	let mut missing_outs = vec![];
	let mut accidental_spend_outs = vec![];
	let mut locked_outs = vec![];

	// check all definitive outputs exist in the wallet outputs
	for deffo in chain_outs.into_iter() {
		let matched_out = wallet_outputs.iter().find(|wo| wo.commit == deffo.commit);
		match matched_out {
			Some(s) => {
				if s.output.status == OutputStatus::Spent {
					accidental_spend_outs.push((s.output.clone(), deffo.clone()));
				}
				if s.output.status == OutputStatus::Locked {
					locked_outs.push((s.output.clone(), deffo.clone()));
				}
			}
			None => missing_outs.push(deffo),
		}
	}

	// mark problem spent outputs as unspent (confirmed against a short-lived fork, for example)
	for m in accidental_spend_outs.into_iter() {
		let mut o = m.0;
		warn!(
			"Output for {} with ID {} ({:?}) marked as spent but exists in UTXO set. \
			 Marking unspent and cancelling any associated transaction log entries.",
			o.value, o.key_id, m.1.commit,
		);
		o.status = OutputStatus::Unspent;
		// any transactions associated with this should be cancelled
		cancel_tx_log_entry(wallet, keychain_mask, &o)?;
		let mut batch = wallet.batch(keychain_mask)?;
		batch.save(o)?;
		batch.commit()?;
	}

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();

	// Restore missing outputs, adding transaction for it back to the log
	for m in missing_outs.into_iter() {
		warn!(
			"Confirmed output for {} with ID {} ({:?}) exists in UTXO set but not in wallet. \
			 Restoring.",
			m.value, m.key_id, m.commit,
		);
		restore_missing_output(wallet, keychain_mask, m, &mut found_parents, &mut None)?;
	}

	if delete_unconfirmed {
		// Unlock locked outputs
		for m in locked_outs.into_iter() {
			let mut o = m.0;
			warn!(
				"Confirmed output for {} with ID {} ({:?}) exists in UTXO set and is locked. \
				 Unlocking and cancelling associated transaction log entries.",
				o.value, o.key_id, m.1.commit,
			);
			o.status = OutputStatus::Unspent;
			cancel_tx_log_entry(wallet, keychain_mask, &o)?;
			let mut batch = wallet.batch(keychain_mask)?;
			batch.save(o)?;
			batch.commit()?;
		}

		let unconfirmed_outs: Vec<&OutputCommitMapping> = wallet_outputs
			.iter()
			.filter(|o| o.output.status == OutputStatus::Unconfirmed)
			.collect();
		// Delete unconfirmed outputs
		for m in unconfirmed_outs.into_iter() {
			let o = m.output.clone();
			warn!(
				"Unconfirmed output for {} with ID {} ({:?}) not in UTXO set. \
				 Deleting and cancelling associated transaction log entries.",
				o.value, o.key_id, m.commit,
			);
			cancel_tx_log_entry(wallet, keychain_mask, &o)?;
			let mut batch = wallet.batch(keychain_mask)?;
			batch.delete(&o.key_id, &o.mmr_index)?;
			batch.commit()?;
		}
	}

	// restore labels, account paths and child derivation indices
	let label_base = "account";
	let mut acct_index = 1;
	for (path, max_child_index) in found_parents.iter() {
		// default path already exists
		if *path != ExtKeychain::derive_key_id(2, 0, 0, 0, 0) {
			let label = format!("{}_{}", label_base, acct_index);
			keys::set_acct_path(wallet, keychain_mask, &label, path)?;
			acct_index += 1;
		}
		let mut batch = wallet.batch(keychain_mask)?;
		debug!("Next child for account {} is {}", path, max_child_index + 1);
		batch.save_child_index(path, max_child_index + 1)?;
		batch.commit()?;
	}
	Ok(())
}

/// Restore a wallet
pub fn restore<'a, T, C, K>(wallet: &mut T, keychain_mask: Option<&SecretKey>) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Don't proceed if wallet_data has anything in it
	let is_empty = wallet.iter().next().is_none();
	if !is_empty {
		error!("Not restoring. Please back up and remove existing db directory first.");
		return Ok(());
	}

	let now = Instant::now();
	warn!("Starting restore.");

	let result_vec = collect_chain_outputs(wallet, keychain_mask)?;

	warn!(
		"Identified {} wallet_outputs as belonging to this wallet",
		result_vec.len(),
	);

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();
	let mut restore_stats = HashMap::new();

	// Now save what we have
	for output in result_vec {
		restore_missing_output(
			wallet,
			keychain_mask,
			output,
			&mut found_parents,
			&mut Some(&mut restore_stats),
		)?;
	}

	// restore labels, account paths and child derivation indices
	let label_base = "account";
	let mut acct_index = 1;
	for (path, max_child_index) in found_parents.iter() {
		// default path already exists
		if *path != ExtKeychain::derive_key_id(2, 0, 0, 0, 0) {
			let label = format!("{}_{}", label_base, acct_index);
			keys::set_acct_path(wallet, keychain_mask, &label, path)?;
			acct_index += 1;
		}
		// restore tx log entry for non-coinbase outputs
		if let Some(s) = restore_stats.get(path) {
			let mut batch = wallet.batch(keychain_mask)?;
			let mut t = TxLogEntry::new(path.clone(), TxLogEntryType::TxReceived, s.log_id);
			t.confirmed = true;
			t.amount_credited = s.amount_credited;
			t.num_outputs = s.num_outputs;
			t.update_confirmation_ts();
			batch.save_tx_log_entry(t, &path)?;
			batch.commit()?;
		}
		let mut batch = wallet.batch(keychain_mask)?;
		batch.save_child_index(path, max_child_index + 1)?;
		debug!("Next child for account {} is {}", path, max_child_index + 1);
		batch.commit()?;
	}

	let mut sec = now.elapsed().as_secs();
	let min = sec / 60;
	sec %= 60;
	info!("Restored wallet in {}m{}s", min, sec);

	Ok(())
}
