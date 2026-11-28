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
//! Functions to restore a wallet's outputs from just the master seed

use crate::api_impl::owner_updater::StatusMessage;
use crate::backend::ScanProgress;
use crate::grin_core::consensus::{valid_header_version, WEEK_HEIGHT};
use crate::grin_core::core::HeaderVersion;
use crate::grin_core::global;
use crate::grin_core::libtx::proof;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::grin_util::secp::{ContextFlag, Secp256k1};
use crate::grin_util::Mutex;
use crate::grin_util::{from_hex, ToHex};
use crate::internal::{keys, updater};
use crate::types::*;
use crate::{wallet_lock, Error, OutputCommitMapping, WalletBatch};
use blake2_rfc::blake2b::blake2b;
use rayon::prelude::*;
use std::cmp;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

fn identify_utxo_outputs<K>(
	keychain: &K,
	outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	percentage_complete: u8,
) -> Result<Vec<OutputResult>, Error>
where
	K: Keychain,
{
	let legacy_builder = proof::LegacyProofBuilder::new(keychain);
	let builder = proof::ProofBuilder::new(keychain);
	let legacy_version = HeaderVersion(1);

	let chain_type = global::get_chain_type();

	let identified = outputs
		.par_iter()
		.map(
			|output| -> Result<Option<(OutputResult, SwitchCommitmentType)>, Error> {
				// set chain type for thread
				global::set_local_chain_type(chain_type);

				let (commit, proof, is_coinbase, height, mmr_index) = output;
				// attempt to unwind message from the RP and get a value
				// will fail if it's not ours
				let info = {
					// Before HF+2wk, try legacy rewind first
					let info_legacy = if valid_header_version(
						height.saturating_sub(2 * WEEK_HEIGHT),
						legacy_version,
					) {
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
					None => return Ok(None),
				};

				let lock_height = if *is_coinbase {
					*height + global::coinbase_maturity()
				} else {
					*height
				};

				Ok(Some((
					OutputResult {
						commit: *commit,
						key_id: key_id.clone(),
						n_child: key_id.to_path().last_path_index(),
						value: amount,
						height: *height,
						lock_height,
						is_coinbase: *is_coinbase,
						mmr_index: *mmr_index,
					},
					switch,
				)))
			},
		)
		.collect::<Result<Vec<_>, Error>>()?;

	let mut wallet_outputs = Vec::new();
	for (output, switch) in identified.into_iter().flatten() {
		let msg = format!(
			"Output found: {:?}, amount: {:?}, key_id: {:?}, mmr_index: {},",
			output.commit, output.value, output.key_id, output.mmr_index,
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

		wallet_outputs.push(output);
	}
	Ok(wallet_outputs)
}

fn collect_chain_outputs_rewind_hash<C>(
	client: C,
	rewind_hash: String,
	start_index: u64,
	end_index: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ViewWallet, Error>
where
	C: NodeClient,
{
	let batch_size = 1000;
	let start_index_stat = start_index;
	let mut start_index = start_index;
	let mut vw = ViewWallet {
		rewind_hash,
		output_result: vec![],
		total_balance: 0,
		last_pmmr_index: 0,
	};
	let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);

	loop {
		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(start_index, end_index, batch_size)?;

		let range = highest_index as f64 - start_index_stat as f64;
		let progress = last_retrieved_index as f64 - start_index_stat as f64;
		let percentage_complete = cmp::min(((progress / range) * 100.0) as u8, 99);

		let msg = format!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, percentage_complete));
		}

		// Scanning outputs
		for output in outputs.iter() {
			let (commit, proof, is_coinbase, height, mmr_index) = output;
			let rewind_hash = from_hex(vw.rewind_hash.as_str())
				.map_err(|e| Error::RewindHash(format!("Unable to decode rewind hash: {}", e)))?;
			let rewind_nonce = blake2b(32, &commit.0, &rewind_hash);
			let nonce = SecretKey::from_slice(&secp, rewind_nonce.as_bytes())
				.map_err(|e| Error::Nonce(format!("Unable to create nonce: {}", e)))?;
			let info = secp.rewind_bullet_proof(*commit, nonce.clone(), None, *proof);

			if info.is_err() {
				continue;
			}

			let info = info?;
			vw.total_balance += info.value;
			let lock_height = if *is_coinbase {
				*height + global::coinbase_maturity()
			} else {
				*height
			};

			let output_info = ViewWalletOutputResult {
				commit: commit.to_hex(),
				value: info.value,
				height: *height,
				mmr_index: *mmr_index,
				is_coinbase: *is_coinbase,
				lock_height,
			};

			vw.output_result.push(output_info);
		}
		if highest_index <= last_retrieved_index {
			vw.last_pmmr_index = last_retrieved_index;
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	Ok(vw)
}

fn collect_chain_outputs<'a, C, K>(
	keychain: &K,
	client: C,
	batch_start_index: u64,
	batch_end_index: u64,
	start_index: u64,
	end_index: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(Vec<OutputResult>, u64, u8), Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let batch_size = 1000;
	let start_index_stat = start_index;
	let mut start_index = batch_start_index;
	let mut result_vec: Vec<OutputResult> = vec![];
	let last_retrieved_return_index;

	let mut perc_complete;
	loop {
		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(start_index, Some(batch_end_index), batch_size)?;

		let range = end_index as f64 - start_index_stat as f64;
		let progress = last_retrieved_index as f64 - start_index_stat as f64;
		perc_complete = cmp::min(((progress / range) * 100.0) as u8, 99);

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
			outputs,
			status_send_channel,
			perc_complete,
		)?);

		debug!(
			"collect_chain_outputs: start_index {}, last_pmmr_index {}",
			start_index, last_retrieved_index
		);

		if highest_index <= last_retrieved_index {
			last_retrieved_return_index = last_retrieved_index;
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	Ok((result_vec, last_retrieved_return_index, perc_complete))
}

const MISSING_OUTPUTS_BATCH_SIZE: usize = 1000;

fn remember_restored_parent(
	parents: &mut BTreeMap<Identifier, Option<u32>>,
	parent: &Identifier,
	key_id: &Identifier,
) {
	let derivation_parent = key_id.parent_path();
	let entry = if keys::is_stateless_receive_key_id(key_id) {
		// Preserve the account of a row already imported by an older wallet.
		// It may have used the immediate derivation parent as its account.
		if *parent == keys::output_parent_key_id(key_id) || *parent == derivation_parent {
			parents.entry(parent.clone()).or_default();
		}
		return;
	} else if *parent == derivation_parent {
		parents.entry(parent.clone()).or_default()
	} else {
		return;
	};
	let child = key_id.to_path().last_path_index();
	*entry = Some(entry.map_or(child, |known| known.max(child)));
}

fn restore_account_metadata<K: Keychain>(
	batch: &mut WalletBatch<'_, K>,
	parents: BTreeMap<Identifier, Option<u32>>,
) -> Result<bool, Error> {
	if parents.is_empty() {
		return Ok(false);
	}
	let accounts: Vec<_> = batch.acct_path_iter()?.collect();
	let mut paths: HashSet<_> = accounts
		.iter()
		.map(|account| account.path.clone())
		.collect();
	let mut labels: HashSet<_> = accounts.into_iter().map(|account| account.label).collect();
	let mut next_label = labels.len();
	let mut changed = false;
	for (path, child) in parents {
		if paths.insert(path.clone()) {
			let label = loop {
				let name = format!("account_{}", next_label);
				next_label += 1;
				if labels.insert(name.clone()) {
					break name;
				}
			};
			batch.save_acct_path(AcctPathMapping {
				label,
				path: path.clone(),
			})?;
			changed = true;
		}
		if let Some(child) = child {
			let next = child.checked_add(1).ok_or_else(|| {
				Error::Backend("Restored output exhausted the account child index".to_owned())
			})?;
			if batch.current_child_index(&path)? < next {
				batch.save_child_index(&path, next)?;
				changed = true;
			}
		}
	}
	Ok(changed)
}

fn restore_missing_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	outputs: Vec<OutputResult>,
	stateless_headers: &HashMap<u64, String>,
	mut legacy_parents: BTreeMap<Identifier, Option<u32>>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	perc_complete: u8,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	for o_chunks in outputs.chunks(MISSING_OUTPUTS_BATCH_SIZE) {
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;
		let mut parents = std::mem::take(&mut legacy_parents);
		for output in o_chunks {
			if let Some(saved) = batch.find_output(&output.key_id, &Some(output.mmr_index))? {
				if saved.value != output.value {
					return Err(Error::Backend(
						"Different output at a saved PMMR position".to_owned(),
					));
				}
				remember_restored_parent(&mut parents, &saved.root_key_id, &saved.key_id);
				continue;
			}
			let msg = format!(
                "Confirmed output for {} with ID {} ({:?}, index {}) exists in UTXO set but not in wallet. \
				 Restoring.",
                output.value, output.key_id, output.commit, output.mmr_index
            );
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
			}

			// Outputs received statelessly belong to their account, but were
			// not allocated from its sequential child index
			let is_stateless = keys::is_stateless_receive_key_id(&output.key_id);
			let parent_key_id = keys::output_parent_key_id(&output.key_id);
			remember_restored_parent(&mut parents, &parent_key_id, &output.key_id);

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

			batch.save(OutputData {
				root_key_id: parent_key_id.clone(),
				key_id: output.key_id.clone(),
				n_child: output.n_child,
				mmr_index: Some(output.mmr_index),
				commit: Some(output.commit.0.to_vec().to_hex()),
				value: output.value,
				status: OutputStatus::Unspent,
				height: output.height,
				lock_height: output.lock_height,
				is_coinbase: output.is_coinbase,
				tx_log_entry: Some(log_id),
				stateless_origin: is_stateless.then(|| StatelessOutputOrigin {
					block_hash: stateless_headers.get(&output.height).cloned(),
					receipt_id: Some(log_id),
					absence: None,
				}),
			})?;
		}
		// The account and child index are committed with the output and
		// receipt. Restarting between chunks cannot strand a receipt.
		restore_account_metadata(&mut batch, parents)?;
		batch.commit()?;
	}

	if !legacy_parents.is_empty() {
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;
		if restore_account_metadata(&mut batch, legacy_parents)? {
			batch.commit()?;
		}
	}
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
	let parent_key_id = output.root_key_id.clone();
	wallet_lock!(wallet_inst, w);
	let updated_tx_entry = if output.tx_log_entry.is_some() {
		let entries = updater::retrieve_txs(
			w,
			output.tx_log_entry,
			None,
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

/// Scan outputs with a given rewind hash view wallet.
/// Retrieve all outputs information that belongs to it.
pub fn scan_rewind_hash<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	rewind_hash: String,
	start_height: u64,
	end_height: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ViewWallet, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning("Starting UTXO scan".to_owned(), 0));
	}
	let client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};
	// Retrieve the actual PMMR index range we're looking for
	let pmmr_range = client.height_range_to_pmmr_indices(start_height, Some(end_height))?;

	let chain_outs = collect_chain_outputs_rewind_hash(
		client,
		rewind_hash,
		pmmr_range.0,
		Some(pmmr_range.1),
		status_send_channel,
	)?;

	let msg = format!(
		"Identified {} wallet_outputs as belonging to this wallet",
		chain_outs.output_result.len(),
	);
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(msg, 99));
	}
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::ScanningComplete(
			"Scanning Complete".to_owned(),
		));
	}
	Ok(chain_outs)
}

/// Check ancestry using the node's selected header chain, scoped to both body tips.
/// Equal body tips work with a NodeClient that has no header-by-height lookup.
/// This check assumes one coherent node view, as do the underlying UTXO calls.
pub(crate) fn scan_tip_is_prefix(
	previous: &(u64, String),
	current: &(u64, String),
	mut header_hash: impl FnMut(u64) -> Result<Option<String>, Error>,
) -> Result<bool, Error> {
	if previous.1.is_empty() || current.1.is_empty() {
		return Ok(false);
	}
	if previous.0 >= current.0 {
		return Ok(previous == current);
	}
	Ok(header_hash(previous.0)?.as_ref() == Some(&previous.1)
		&& header_hash(current.0)?.as_ref() == Some(&current.1))
}

#[cfg(test)]
mod scan_snapshot_tests {
	use super::scan_tip_is_prefix;

	#[test]
	fn same_tip_needs_no_optional_header_lookup() {
		let anchor = (10, "original tip".to_owned());
		assert!(scan_tip_is_prefix(&anchor, &anchor, |_| unreachable!()).unwrap());
	}

	#[test]
	fn advance_only_when_both_body_tips_are_on_the_header_chain() {
		let anchor = (10, "original tip".to_owned());
		let later = (13, "later tip".to_owned());
		let cases = [
			(Some(anchor.1.as_str()), Some(later.1.as_str()), true),
			(Some("different ancestor"), Some(later.1.as_str()), false),
			(Some(anchor.1.as_str()), Some("header-only tip"), false),
			(None, None, false),
		];
		for (previous_hash, current_hash, expected) in cases {
			let result = scan_tip_is_prefix(&anchor, &later, |height| {
				Ok(match height {
					10 => previous_hash,
					13 => current_hash,
					_ => unreachable!(),
				}
				.map(str::to_owned))
			});
			assert_eq!(result.unwrap(), expected);
		}
	}

	#[test]
	fn a_replaced_or_lower_tip_cannot_extend_the_scan() {
		let anchor = (10, "original tip".to_owned());
		let other_at_same_height = (10, "replaced tip".to_owned());
		let lower = (9, "lower tip".to_owned());
		let unidentified = (10, String::new());
		for current in [&other_at_same_height, &lower, &unidentified] {
			assert!(!scan_tip_is_prefix(&anchor, current, |_| unreachable!()).unwrap());
		}
	}
}

/// Scan chain outputs and repair the wallet state where needed.
///
/// This is the low-level worker used by the owner API. Callers should normally
/// use the owner scan/update methods instead of calling this directly, unless
/// they need to drive a scan in batches and save progress between those batches.
///
/// `batch_start_height` and `batch_end_height` describe the part of the chain
/// scanned by this call. `start_height` and `end_height` describe the full scan
/// range, so progress and PMMR bounds still reflect the whole scan.
///
/// The returned `ScannedBlockInfo` is the progress marker to persist after the
/// batch. The returned PMMR range can be passed into the next batch to avoid
/// looking up the full range again.
pub fn scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	delete_unconfirmed: bool,
	batch_start_height: u64,
	batch_end_height: u64,
	start_height: u64,
	end_height: u64,
	total_pmmr_range: Option<(u64, u64)>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(ScannedBlockInfo, (u64, u64)), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (progress, range) = scan_at(
		wallet_inst,
		keychain_mask,
		delete_unconfirmed,
		batch_start_height,
		batch_end_height,
		start_height,
		end_height,
		total_pmmr_range,
		None,
		status_send_channel,
	)?;
	Ok((progress.cursor, range))
}

/// Scan one batch of a fixed range. The prior observed body tip must
/// remain on the selected chain, even when it is above the range end.
pub(crate) fn scan_at<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	delete_unconfirmed: bool,
	batch_start_height: u64,
	batch_end_height: u64,
	start_height: u64,
	end_height: u64,
	total_pmmr_range: Option<(u64, u64)>,
	scan_tip: Option<&(u64, String)>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(ScanProgress, (u64, u64)), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// First, get a definitive list of outputs we own from the chain
	if let Some(ref s) = status_send_channel {
		if start_height == batch_start_height {
			let _ = s.send(StatusMessage::Scanning("Starting UTXO scan".to_owned(), 0));
		}
	}
	let (client, keychain) = {
		wallet_lock!(wallet_inst, w);
		(w.w2n_client().clone(), w.keychain(keychain_mask)?)
	};

	let tip = client.get_chain_tip()?;
	let anchor = scan_tip.unwrap_or(&tip);
	if batch_end_height > end_height
		|| end_height > anchor.0
		|| !scan_tip_is_prefix(anchor, &tip, |height| client.get_header_hash(height))?
	{
		return Err(Error::ScanInterrupted(
			"Scan range is no longer on the node's block chain".to_owned(),
		));
	}

	// Retrieve total PMMR index range we're looking for
	let total_pmmr_range = if let Some(total_range) = total_pmmr_range {
		total_range
	} else {
		client.height_range_to_pmmr_indices(start_height, Some(end_height))?
	};

	// Retrieve current batch PMMR index range
	let pmmr_range =
		client.height_range_to_pmmr_indices(batch_start_height, Some(batch_end_height))?;

	debug!(
		"scan: from: {}, to: {}",
		batch_start_height, batch_end_height
	);

	let (chain_outs, last_index, perc_complete) = collect_chain_outputs(
		&keychain,
		client.clone(),
		pmmr_range.0,
		pmmr_range.1,
		total_pmmr_range.0,
		total_pmmr_range.1,
		status_send_channel,
	)?;
	let msg = format!(
		"Identified {} wallet_outputs as belonging to this wallet",
		chain_outs.len(),
	);
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
	}

	// Now, get all outputs owned by this wallet (regardless of account)
	let wallet_outputs = {
		wallet_lock!(wallet_inst, w);
		updater::retrieve_outputs(w, keychain_mask, true, None, None)?
	};

	let mut missing_outs = vec![];
	let mut accidental_spend_outs = vec![];
	let mut stateless_returns = vec![];
	let mut locked_outs = vec![];

	// check all definitive outputs exist in the wallet outputs
	for deffo in chain_outs.into_iter() {
		let matched_out = wallet_outputs.iter().find(|wo| wo.commit == deffo.commit);
		match matched_out {
			Some(s) => {
				if keys::is_stateless_receive_key_id(&s.output.key_id)
					&& (matches!(
						s.output.status,
						OutputStatus::Spent | OutputStatus::Reverted
					) || s.output.stateless_absence().is_some()
						|| s.output.height != deffo.height
						|| s.output.mmr_index != Some(deffo.mmr_index))
				{
					stateless_returns.push((s.output.clone(), deffo));
					continue;
				}
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

	let mut stateless_heights: BTreeSet<u64> = missing_outs
		.iter()
		.filter(|output| keys::is_stateless_receive_key_id(&output.key_id))
		.map(|output| output.height)
		.chain(stateless_returns.iter().map(|(_, output)| output.height))
		.collect();
	if stateless_heights
		.iter()
		.any(|height| *height > batch_end_height)
	{
		return Err(Error::ClientCallback(
			"Stateless output is above the scan batch".to_owned(),
		));
	}
	if scan_tip.is_some() {
		stateless_heights.insert(batch_end_height);
	}
	let finish_observation = || {
		let after = client.get_chain_tip()?;
		if after != tip {
			return Err(Error::ScanInterrupted(
				"Node body tip changed during scan batch".to_owned(),
			));
		}
		Ok(after)
	};
	let stateless_headers = if stateless_heights.is_empty() {
		finish_observation()?;
		HashMap::new()
	} else {
		updater::stateless_headers(&client, &tip, stateless_heights, finish_observation)?
	};
	let cursor_hash = match scan_tip {
		Some(anchor) if batch_end_height == anchor.0 => anchor.1.clone(),
		Some(_) => stateless_headers
			.get(&batch_end_height)
			.cloned()
			.unwrap_or_default(),
		None => String::new(),
	};
	if !stateless_returns.is_empty() {
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;
		for (previous, current) in stateless_returns {
			// Re-read before applying: a payment might have locked this coin
			// while the scan was fetching headers.
			if let Ok(output) = batch.get(&previous.key_id, &previous.mmr_index) {
				updater::update_stateless_output(
					&mut batch,
					output,
					Some((current.height, current.mmr_index)),
					stateless_headers.get(&current.height),
				)?;
				if delete_unconfirmed {
					let restored = batch.get(&previous.key_id, &Some(current.mmr_index))?;
					if restored.status == OutputStatus::Locked {
						locked_outs.push((restored, current));
					}
				}
			}
		}
		batch.commit()?;
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
			let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
		}
		o.status = OutputStatus::Unspent;
		// any transactions associated with this should be canceled
		cancel_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;
		batch.save(o)?;
		batch.commit()?;
	}

	// Repair rows imported by versions that committed accounts separately.
	// Include spent rows, which do not appear in the node's UTXO scan.
	let mut legacy_parents = BTreeMap::new();
	for saved in &wallet_outputs {
		remember_restored_parent(
			&mut legacy_parents,
			&saved.output.root_key_id,
			&saved.output.key_id,
		);
	}

	debug!("scan: restoring {} missing outputs", missing_outs.len());

	// Restore missing outputs, adding transaction for it back to the log
	restore_missing_outputs(
		wallet_inst.clone(),
		keychain_mask,
		missing_outs,
		&stateless_headers,
		legacy_parents,
		status_send_channel,
		perc_complete,
	)?;

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
				let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
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
				let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
			}
			cancel_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
			wallet_lock!(wallet_inst, w);
			let mut batch = w.batch(keychain_mask)?;
			batch.delete(&o.key_id, &o.mmr_index)?;
			batch.commit()?;
		}
	}

	if let Some(ref s) = status_send_channel {
		if end_height == batch_end_height {
			let _ = s.send(StatusMessage::ScanningComplete(
				"Scanning Complete".to_owned(),
			));
		}
	}

	Ok((
		ScanProgress {
			cursor: ScannedBlockInfo {
				height: batch_end_height,
				hash: cursor_hash,
				start_pmmr_index: pmmr_range.0,
				last_pmmr_index: last_index,
			},
			utxo_tip: Some(tip),
		},
		total_pmmr_range,
	))
}
