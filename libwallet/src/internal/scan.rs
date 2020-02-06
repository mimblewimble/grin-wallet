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

use crate::api_impl::owner_updater::StatusMessage;
use crate::grin_core::consensus::{valid_header_version, WEEK_HEIGHT};
use crate::grin_core::core::HeaderVersion;
use crate::grin_core::global;
use crate::grin_core::libtx::proof;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::grin_util::Mutex;
use crate::internal::{keys, updater};
use crate::types::*;
use crate::{wallet_lock, Error, OutputCommitMapping};
use std::cmp;
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::Arc;

/// Utility struct for return values from below
#[derive(Debug, Clone)]
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

fn identify_utxo_outputs<'a, K>(
	keychain: &K,
	outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	percentage_complete: u8,
) -> Result<Vec<OutputResult>, Error>
where
	K: Keychain + 'a,
{
	let mut wallet_outputs: Vec<OutputResult> = Vec::new();

	let legacy_builder = proof::LegacyProofBuilder::new(keychain);
	let builder = proof::ProofBuilder::new(keychain);
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

		let msg = format!(
			"Output found: {:?}, amount: {:?}, key_id: {:?}, mmr_index: {},",
			commit, amount, key_id, mmr_index,
		);

		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, percentage_complete));
		}

		if switch != SwitchCommitmentType::Regular {
			let msg = format!("Unexpected switch commitment type {:?}", switch);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::UpdateWarning(msg));
			}
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

fn collect_chain_outputs<'a, C, K>(
	keychain: &K,
	client: C,
	start_index: u64,
	end_index: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(Vec<OutputResult>, u64), Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let batch_size = 1000;
	let start_index_stat = start_index;
	let mut start_index = start_index;
	let mut result_vec: Vec<OutputResult> = vec![];
	let last_retrieved_return_index;
	loop {
		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(start_index, end_index, batch_size)?;

		let range = highest_index as f64 - start_index_stat as f64;
		let progress = last_retrieved_index as f64 - start_index_stat as f64;
		let perc_complete = cmp::min(((progress / range) * 100.0) as u8, 99);

		let msg = format!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
		}

		result_vec.append(&mut identify_utxo_outputs(
			keychain,
			outputs.clone(),
			status_send_channel,
			perc_complete as u8,
		)?);

		if highest_index <= last_retrieved_index {
			last_retrieved_return_index = last_retrieved_index;
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	Ok((result_vec, last_retrieved_return_index))
}

///
fn restore_missing_output<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	output: OutputResult,
	found_parents: &mut HashMap<Identifier, u32>,
	tx_stats: &mut Option<&mut HashMap<Identifier, RestoredTxStats>>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let commit = w.calc_commit_for_cache(keychain_mask, output.value, &output.key_id)?;
	let mut batch = w.batch(keychain_mask)?;

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
	} else if let Some(ref mut s) = tx_stats {
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

	let max_child_index = *found_parents.get(&parent_key_id).unwrap();
	if output.n_child >= max_child_index {
		found_parents.insert(parent_key_id, output.n_child);
	}

	batch.commit()?;
	Ok(())
}

///
fn cancel_tx_log_entry<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	output: &OutputData,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = output.key_id.parent_path();
	wallet_lock!(wallet_inst, w);
	let updated_tx_entry = if output.tx_log_entry.is_some() {
		let entries = updater::retrieve_txs(
			&mut **w,
			output.tx_log_entry,
			None,
			Some(&parent_key_id),
			false,
		)?;
		if !entries.is_empty() {
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
	let mut batch = w.batch(keychain_mask)?;
	if let Some(t) = updated_tx_entry {
		batch.save_tx_log_entry(t, &parent_key_id)?;
	}
	batch.commit()?;
	Ok(())
}

/// Check / repair wallet contents by scanning against chain
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	delete_unconfirmed: bool,
	start_height: u64,
	end_height: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ScannedBlockInfo, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// First, get a definitive list of outputs we own from the chain
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning("Starting UTXO scan".to_owned(), 0));
	}
	let (client, keychain) = {
		wallet_lock!(wallet_inst, w);
		(w.w2n_client().clone(), w.keychain(keychain_mask)?)
	};

	// Retrieve the actual PMMR index range we're looking for
	let pmmr_range = client.height_range_to_pmmr_indices(start_height, Some(end_height))?;

	let (chain_outs, last_index) = collect_chain_outputs(
		&keychain,
		client,
		pmmr_range.0,
		Some(pmmr_range.1),
		status_send_channel,
	)?;
	let msg = format!(
		"Identified {} wallet_outputs as belonging to this wallet",
		chain_outs.len(),
	);

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(msg, 99));
	}

	// Now, get all outputs owned by this wallet (regardless of account)
	let wallet_outputs = {
		wallet_lock!(wallet_inst, w);
		updater::retrieve_outputs(&mut **w, keychain_mask, true, None, None)?
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
		let msg = format!(
			"Output for {} with ID {} ({:?}) marked as spent but exists in UTXO set. \
			 Marking unspent and cancelling any associated transaction log entries.",
			o.value, o.key_id, m.1.commit,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, 99));
		}
		o.status = OutputStatus::Unspent;
		// any transactions associated with this should be cancelled
		cancel_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;
		batch.save(o)?;
		batch.commit()?;
	}

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();

	// Restore missing outputs, adding transaction for it back to the log
	for m in missing_outs.into_iter() {
		let msg = format!(
				"Confirmed output for {} with ID {} ({:?}, index {}) exists in UTXO set but not in wallet. \
				 Restoring.",
				m.value, m.key_id, m.commit, m.mmr_index
			);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, 99));
		}
		restore_missing_output(
			wallet_inst.clone(),
			keychain_mask,
			m,
			&mut found_parents,
			&mut None,
		)?;
	}

	if delete_unconfirmed {
		// Unlock locked outputs
		for m in locked_outs.into_iter() {
			let mut o = m.0;
			let msg = format!(
				"Confirmed output for {} with ID {} ({:?}) exists in UTXO set and is locked. \
				 Unlocking and cancelling associated transaction log entries.",
				o.value, o.key_id, m.1.commit,
			);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Scanning(msg, 99));
			}
			o.status = OutputStatus::Unspent;
			cancel_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
			wallet_lock!(wallet_inst, w);
			let mut batch = w.batch(keychain_mask)?;
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
			let msg = format!(
				"Unconfirmed output for {} with ID {} ({:?}) not in UTXO set. \
				 Deleting and cancelling associated transaction log entries.",
				o.value, o.key_id, m.commit,
			);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Scanning(msg, 99));
			}
			cancel_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
			wallet_lock!(wallet_inst, w);
			let mut batch = w.batch(keychain_mask)?;
			batch.delete(&o.key_id, &o.mmr_index)?;
			batch.commit()?;
		}
	}

	// restore labels, account paths and child derivation indices
	wallet_lock!(wallet_inst, w);
	let label_base = "account";
	let accounts: Vec<Identifier> = w.acct_path_iter().map(|m| m.path).collect();
	let mut acct_index = accounts.len();
	for (path, max_child_index) in found_parents.iter() {
		// Only restore paths that don't exist
		if !accounts.contains(path) {
			let label = format!("{}_{}", label_base, acct_index);
			let msg = format!("Setting account {} at path {}", label, path);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Scanning(msg, 99));
			}
			keys::set_acct_path(&mut **w, keychain_mask, &label, path)?;
			acct_index += 1;
		}
		let current_child_index = w.current_child_index(&path)?;
		if *max_child_index >= current_child_index {
			let mut batch = w.batch(keychain_mask)?;
			debug!("Next child for account {} is {}", path, max_child_index + 1);
			batch.save_child_index(path, max_child_index + 1)?;
			batch.commit()?;
		}
	}

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::ScanningComplete(
			"Scanning Complete".to_owned(),
		));
	}

	Ok(ScannedBlockInfo {
		height: end_height,
		hash: "".to_owned(),
		start_pmmr_index: pmmr_range.0,
		last_pmmr_index: last_index,
	})
}
