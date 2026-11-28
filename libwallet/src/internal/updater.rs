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

use std::collections::{BTreeSet, HashMap, HashSet};
use uuid::Uuid;

use crate::backend::StatelessHeaderCache;
use crate::error::Error;
use crate::grin_core::consensus::reward;
use crate::grin_core::core::{CommitWrapper, Output, TxKernel};
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
	NodeClient, OutputData, OutputStatus, StatelessOutputAbsence, StatelessOutputOrigin,
	TxLogEntry, TxLogEntryType, WalletInfo,
};
use crate::{
	BlockFees, CbData, OutputCommitMapping, RetrieveTxQueryArgs, RetrieveTxQuerySortField,
	RetrieveTxQuerySortOrder, WalletBackend, WalletBatch,
};

use num_bigint::BigInt;

/// Retrieve all the outputs (don't attempt to update from node)
pub fn retrieve_outputs<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	show_spent: bool,
	tx_id: Option<u32>,
	parent_key_id: Option<&Identifier>,
) -> Result<Vec<OutputCommitMapping>, Error>
where
	C: NodeClient,
	K: Keychain,
{
	// just read the wallet here, no need for a write lock
	let mut outputs = wallet
		.iter()?
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

/// Apply advanced filtering to resultset from retrieve_txs below
fn apply_advanced_tx_list_filtering<C, K>(
	wallet: &mut WalletBackend<C, K>,
	parent_key_id: Option<&Identifier>,
	query_args: &RetrieveTxQueryArgs,
) -> Result<Vec<TxLogEntry>, Error>
where
	C: NodeClient,
	K: Keychain,
{
	// Apply simple bool, GTE or LTE fields
	let mut bad_records = 0;
	let txs_iter = wallet
		.tx_log_iter()?
		.filter(|tx| {
			if tx.is_err() {
				bad_records += 1;
			}
			tx.is_ok()
		})
		.map(|tx| tx.unwrap())
		.filter(|tx_entry| match parent_key_id {
			Some(k) => tx_entry.parent_key_id == *k,
			None => true,
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.exclude_cancelled {
				if v {
					tx_entry.tx_type != TxLogEntryType::TxReceivedCancelled
						&& tx_entry.tx_type != TxLogEntryType::TxSentCancelled
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.include_outstanding_only {
				if v {
					!tx_entry.confirmed
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.include_confirmed_only {
				if v {
					tx_entry.confirmed
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.include_sent_only {
				if v {
					tx_entry.tx_type == TxLogEntryType::TxSent
						|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.include_received_only {
				if v {
					tx_entry.tx_type == TxLogEntryType::TxReceived
						|| tx_entry.tx_type == TxLogEntryType::TxReceivedCancelled
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.include_coinbase_only {
				if v {
					tx_entry.tx_type == TxLogEntryType::ConfirmedCoinbase
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.include_reverted_only {
				if v {
					tx_entry.tx_type == TxLogEntryType::TxReverted
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.min_id {
				tx_entry.id >= v
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.max_id {
				tx_entry.id <= v
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.min_amount {
				if tx_entry.tx_type == TxLogEntryType::TxSent
					|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
				{
					BigInt::from(tx_entry.amount_debited) - BigInt::from(tx_entry.amount_credited)
						>= BigInt::from(v)
				} else {
					BigInt::from(tx_entry.amount_credited) - BigInt::from(tx_entry.amount_debited)
						>= BigInt::from(v)
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.max_amount {
				if tx_entry.tx_type == TxLogEntryType::TxSent
					|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
				{
					BigInt::from(tx_entry.amount_debited) - BigInt::from(tx_entry.amount_credited)
						<= BigInt::from(v)
				} else {
					BigInt::from(tx_entry.amount_credited) - BigInt::from(tx_entry.amount_debited)
						<= BigInt::from(v)
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.min_creation_timestamp {
				tx_entry.creation_ts >= v
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.max_creation_timestamp {
				tx_entry.creation_ts <= v
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.min_confirmed_timestamp {
				if let Some(t) = tx_entry.confirmation_ts {
					t >= v
				} else {
					true
				}
			} else {
				true
			}
		})
		.filter(|tx_entry| {
			if let Some(v) = query_args.max_confirmed_timestamp {
				if let Some(t) = tx_entry.confirmation_ts {
					t <= v
				} else {
					true
				}
			} else {
				true
			}
		});
	// };

	//TODO: apply limit + introduce skip before collecting all records.
	// Introduce comparator for LMDB to not request all records with limit.
	let mut return_txs: Vec<TxLogEntry> = txs_iter.collect();

	if bad_records != 0 {
		error!("apply_advanced_tx_list_filtering: tx history is missing {} records, cause db read error", bad_records);
	}

	// Now apply requested sorting
	if let Some(ref s) = query_args.sort_field {
		match s {
			RetrieveTxQuerySortField::Id => {
				return_txs.sort_by_key(|tx| tx.id);
			}
			RetrieveTxQuerySortField::CreationTimestamp => {
				return_txs.sort_by_key(|tx| tx.creation_ts);
			}
			RetrieveTxQuerySortField::ConfirmationTimestamp => {
				return_txs.sort_by_key(|tx| tx.confirmation_ts);
			}
			RetrieveTxQuerySortField::TotalAmount => {
				return_txs.sort_by_key(|tx| {
					if tx.tx_type == TxLogEntryType::TxSent
						|| tx.tx_type == TxLogEntryType::TxSentCancelled
					{
						BigInt::from(tx.amount_debited) - BigInt::from(tx.amount_credited)
					} else {
						BigInt::from(tx.amount_credited) - BigInt::from(tx.amount_debited)
					}
				});
			}
			RetrieveTxQuerySortField::AmountCredited => {
				return_txs.sort_by_key(|tx| tx.amount_credited);
			}
			RetrieveTxQuerySortField::AmountDebited => {
				return_txs.sort_by_key(|tx| tx.amount_debited);
			}
		}
	} else {
		return_txs.sort_by_key(|tx| tx.id);
	}

	if let Some(ref s) = query_args.sort_order {
		match s {
			RetrieveTxQuerySortOrder::Desc => return_txs.reverse(),
			_ => {}
		}
	}

	// Apply limit if requested
	if let Some(l) = query_args.limit {
		return_txs = return_txs.into_iter().take(l as usize).collect()
	}

	Ok(return_txs)
}

/// Retrieve all the transaction entries, or a particular entry
/// if `parent_key_id` is set, only return entries from that key
pub fn retrieve_txs<C, K>(
	wallet: &mut WalletBackend<C, K>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
	query_args: Option<RetrieveTxQueryArgs>,
	parent_key_id: Option<&Identifier>,
	outstanding_only: bool,
) -> Result<Vec<TxLogEntry>, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let mut txs;
	// Adding in new transaction list query logic. If `tx_id` or `tx_slate_id`
	// is provided, then `query_args` is ignored and old logic is followed.
	if query_args.is_some() && tx_id.is_none() && tx_slate_id.is_none() {
		txs = apply_advanced_tx_list_filtering(wallet, parent_key_id, &query_args.unwrap())?
	} else {
		let mut bad_records = 0;
		txs = wallet
			.tx_log_iter()?
			.filter(|tx| {
				if tx.is_err() {
					bad_records += 1;
				}
				tx.is_ok()
			})
			.map(|tx| tx.unwrap())
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
		if bad_records != 0 {
			error!(
				"retrieve_txs: tx history is missing {} records, cause db read error",
				bad_records
			);
		}
		txs.sort_by_key(|tx| tx.creation_ts);
	}
	Ok(txs)
}

/// Refreshes the outputs in a wallet with the latest information
/// from a node
/// Also removes stale unconfirmed coinbase outputs across all accounts
pub fn refresh_outputs<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	refresh_outputs_observed(wallet, keychain_mask, parent_key_id, update_all).map(|_| ())
}

/// Return the body tip used for the output observation.
pub(crate) fn refresh_outputs_observed<C: NodeClient, K: Keychain>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<(u64, String), Error> {
	let tip = wallet.w2n_client().get_chain_tip()?;
	refresh_output_state(wallet, keychain_mask, &tip, parent_key_id, update_all)?;
	Ok(tip)
}

/// Build a local map of wallet outputs keyed by commit.
/// The map keys identify outputs to query from the node.
/// If `update_all` is `false`, select stateless outputs, outstanding
/// transactions' outputs, and outputs without a transaction log entry.
/// Returns mapping of output commit to tuple of derived key for output,
/// PMMR index, tx entry log identifier and check if output is unspent
pub fn map_wallet_outputs<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<HashMap<pedersen::Commitment, (Identifier, Option<u64>, Option<u32>, bool)>, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let mut wallet_outputs = HashMap::new();
	let keychain = wallet.keychain(keychain_mask)?;
	let unspents: Vec<OutputData> = wallet
		.iter()?
		.filter(|x| {
			x.root_key_id == *parent_key_id
				&& (x.status != OutputStatus::Spent || keys::is_stateless_receive_key_id(&x.key_id))
		})
		.collect();

	let tx_entries = retrieve_txs(wallet, None, None, None, Some(&parent_key_id), true)?;

	// Stateless receipts have no stored kernel to fall back on. Keep checking
	// their UTXOs even after the incoming log entry was confirmed.
	let unspents = match update_all {
		false => unspents
			.into_iter()
			.filter(|x| {
				keys::is_stateless_receive_key_id(&x.key_id)
					|| x.tx_log_entry
						.map_or(true, |id| tx_entries.iter().any(|entry| entry.id == id))
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
pub fn cancel_tx_and_outputs<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	mut tx: TxLogEntry,
	outputs: Vec<OutputData>,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let mut batch = wallet.batch(keychain_mask)?;

	for mut o in outputs {
		// unlock locked outputs
		let keep_stateless_input =
			tx.tx_type == TxLogEntryType::TxSent && o.stateless_origin.is_some();
		if o.status == OutputStatus::Unconfirmed
			|| (o.status == OutputStatus::Reverted && !keep_stateless_input)
		{
			batch.delete(&o.key_id, &o.mmr_index)?;
		}
		if o.status == OutputStatus::Locked {
			o.status = if o.stateless_absence().is_some() {
				OutputStatus::Reverted
			} else {
				OutputStatus::Unspent
			};
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

/// Resolve creation headers against the body tip used for the UTXO query.
/// The node is trusted as elsewhere in the wallet. These checks avoid using
/// two visibly different views as a single observation.
pub(super) fn stateless_headers<C: NodeClient>(
	client: &C,
	tip: &(u64, String),
	heights: BTreeSet<u64>,
	finish_observation: impl FnOnce() -> Result<(u64, String), Error>,
) -> Result<HashMap<u64, String>, Error> {
	resolve_stateless_headers(
		tip,
		heights,
		None,
		|height| client.get_header_hash(height),
		finish_observation,
	)
}

fn resolve_stateless_headers(
	tip: &(u64, String),
	heights: BTreeSet<u64>,
	previous: Option<&StatelessHeaderCache>,
	mut header_hash: impl FnMut(u64) -> Result<Option<String>, Error>,
	body_tip: impl FnOnce() -> Result<(u64, String), Error>,
) -> Result<HashMap<u64, String>, Error> {
	let mut headers = HashMap::new();
	if heights.is_empty() {
		return Ok(headers);
	}

	if let Some(header_tip) = header_hash(tip.0)? {
		if header_tip != tip.1 {
			return Err(Error::ClientCallback(
				"Header and block tips disagree".to_owned(),
			));
		}
		// A canonical prefix authenticates the previously read header hashes,
		// independently of what outputs the database currently contains.
		let reusable = match previous {
			Some(cache) if cache.tip == *tip => Some(cache),
			Some(cache)
				if cache.tip.0 < tip.0
					&& header_hash(cache.tip.0)?.as_ref() == Some(&cache.tip.1) =>
			{
				Some(cache)
			}
			_ => None,
		};
		for height in heights.into_iter().filter(|height| *height <= tip.0) {
			let cached = reusable.and_then(|cache| cache.headers.get(&height));
			let hash = if height == tip.0 {
				header_tip.clone()
			} else if let Some(hash) = cached {
				hash.clone()
			} else {
				header_hash(height)?.ok_or_else(|| {
					Error::ClientCallback("Missing header for a stateless output".to_owned())
				})?
			};
			headers.insert(height, hash);
		}
		if header_hash(tip.0)?.as_ref() != Some(&header_tip) {
			return Err(Error::ClientCallback(
				"Header chain changed during refresh".to_owned(),
			));
		}
	}
	if &body_tip()? != tip {
		return Err(Error::ClientCallback(
			"Block tip changed during refresh".to_owned(),
		));
	}
	Ok(headers)
}

/// Apply a stateless observation and its receipt in one database batch.
pub(super) fn update_stateless_output<K: Keychain>(
	batch: &mut WalletBatch<'_, K>,
	mut output: OutputData,
	live: Option<(u64, u64)>,
	header: Option<&String>,
) -> Result<(), Error> {
	let previous = output.clone();
	let mut origin = output
		.stateless_origin
		.take()
		.unwrap_or(StatelessOutputOrigin {
			block_hash: None,
			receipt_id: None,
			absence: None,
		});
	let receipt = match origin.receipt_id.or(output.tx_log_entry) {
		Some(id) => batch
			.get_tx_log_entry(&output.root_key_id, id)?
			.filter(|entry| {
				matches!(
					entry.tx_type,
					TxLogEntryType::TxReceived | TxLogEntryType::TxReverted
				)
			}),
		None => None,
	};
	if let Some(ref entry) = receipt {
		origin.receipt_id = Some(entry.id);
	}

	match live {
		Some((height, index)) => {
			if output.mmr_index != Some(index) {
				if batch.get(&output.key_id, &Some(index)).is_ok() {
					return Err(Error::Backend(
						"Duplicate stateless output position".to_owned(),
					));
				}
				batch.delete(&output.key_id, &output.mmr_index)?;
				output.mmr_index = Some(index);
			}
			output.height = height;
			output.lock_height = height;
			origin.block_hash = header.cloned();
			origin.absence = None;

			// A live output does not cancel an outgoing payment's reservation.
			if output.status != OutputStatus::Locked && output.tx_log_entry != origin.receipt_id {
				let outgoing = match output.tx_log_entry {
					Some(id) => batch.get_tx_log_entry(&output.root_key_id, id)?,
					None => None,
				};
				if outgoing.map_or(false, |entry| entry.tx_type == TxLogEntryType::TxSent) {
					output.status = OutputStatus::Locked;
				}
			}
			if output.status != OutputStatus::Locked {
				output.status = OutputStatus::Unspent;
			}
		}
		None => match (origin.block_hash.as_ref(), header) {
			(Some(original), Some(canonical)) if original == canonical => {
				output.status = OutputStatus::Spent;
				origin.absence = None;
			}
			(original, canonical) => {
				let absence = if original.zip(canonical).is_some() {
					StatelessOutputAbsence::Reverted
				} else {
					StatelessOutputAbsence::Unverified
				};
				origin.absence = Some(absence);
				if output.status != OutputStatus::Locked {
					output.status = OutputStatus::Reverted;
				}
			}
		},
	}
	if let Some(mut entry) = receipt {
		let confirmed = origin.absence.is_none();
		let entry_type = if origin.absence == Some(StatelessOutputAbsence::Reverted) {
			TxLogEntryType::TxReverted
		} else {
			TxLogEntryType::TxReceived
		};
		if entry.confirmed != confirmed || entry.tx_type != entry_type {
			if confirmed {
				entry.update_confirmation_ts();
			}
			entry.reverted_after = if entry_type == TxLogEntryType::TxReverted {
				entry
					.confirmation_ts
					.and_then(|ts| (chrono::Utc::now() - ts).to_std().ok())
			} else {
				None
			};
			entry.confirmed = confirmed;
			entry.tx_type = entry_type;
			batch.save_tx_log_entry(entry, &output.root_key_id)?;
		}
	}
	output.stateless_origin = Some(origin);
	if previous != output {
		batch.save(output)?;
	}
	Ok(())
}

/// Apply refreshed API output data to the wallet
fn apply_api_outputs<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	wallet_outputs: &HashMap<pedersen::Commitment, (Identifier, Option<u64>, Option<u32>, bool)>,
	api_outputs: &HashMap<pedersen::Commitment, (String, u64, u64)>,
	reverted_kernels: HashSet<u32>,
	stateless_sends: Vec<(TxLogEntry, Vec<OutputData>)>,
	stateless_headers: &HashMap<u64, String>,
	height: u64,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	// now for each commit, find the output in the wallet and the corresponding
	// api output (if it exists) and refresh it in-place in the wallet.
	// Note: minimizing the time we spend holding the wallet lock.
	{
		let last_confirmed_height = wallet.last_confirmed_height_for_parent(parent_key_id)?;
		// If the server height is less than our confirmed height, don't apply
		// these changes as the chain is syncing, incorrect or forking
		if height < last_confirmed_height {
			if wallet_outputs
				.values()
				.any(|(id, _, _, _)| keys::is_stateless_receive_key_id(id))
			{
				return Err(Error::ClientCallback(
					"Block tip is below the last wallet update".to_owned(),
				));
			}
			warn!(
				"Not updating outputs as the height of the node's chain \
				 is less than the last reported wallet update height."
			);
			warn!("Please wait for sync on node to complete or fork to resolve and try again.");
			return Ok(());
		}
		let reconciled_sends: HashSet<_> = stateless_sends.iter().map(|(tx, _)| tx.id).collect();
		let mut batch = wallet.batch(keychain_mask)?;
		for (commit, (id, mmr_index, _, _)) in wallet_outputs.iter() {
			if let Ok(mut output) = batch.get(id, mmr_index) {
				if keys::is_stateless_receive_key_id(id) {
					let live = api_outputs
						.get(commit)
						.map(|(_, height, index)| (*height, *index));
					let origin_height = live.map_or(output.height, |(height, _)| height);
					update_stateless_output(
						&mut batch,
						output,
						live,
						stateless_headers.get(&origin_height),
					)?;
					continue;
				}
				if output
					.tx_log_entry
					.map_or(false, |id| reconciled_sends.contains(&id))
				{
					continue;
				}
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
							let tx = batch
								.tx_log_iter()?
								.filter(|t| t.is_ok())
								.map(|t| t.unwrap())
								.find(|t| {
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
							} else {
								if let Some(tx_id) = output.tx_log_entry {
									error!("apply_api_outputs: tx with id {:?} not found", tx_id);
								}
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

		let mut txs_to_save = vec![];
		let mut bad_records = 0;
		for mut tx in batch
			.tx_log_iter()?
			.filter(|tx| {
				if tx.is_err() {
					bad_records += 1;
				}
				tx.is_ok()
			})
			.map(|t| t.unwrap())
		{
			if reverted_kernels.contains(&tx.id) && tx.parent_key_id == *parent_key_id {
				tx.tx_type = TxLogEntryType::TxReverted;
				tx.reverted_after = tx.confirmation_ts.clone().and_then(|t| {
					let now = chrono::Utc::now();
					(now - t).to_std().ok()
				});
				tx.confirmed = false;
				txs_to_save.push(tx);
			}
		}

		if bad_records > 0 {
			error!(
				"apply_api_outputs: tx history is missing {} records, cause db read error",
				bad_records
			);
		}

		for tx in txs_to_save {
			batch.save_tx_log_entry(tx, &parent_key_id)?;
		}

		for (tx, outputs) in stateless_sends {
			for output in outputs {
				batch.save(output)?;
			}
			batch.save_tx_log_entry(tx, parent_key_id)?;
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
fn refresh_output_state<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	tip: &(u64, String),
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
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
	let stateless_sends = reconcile_stateless_sends(
		wallet,
		keychain_mask,
		&wallet_outputs,
		&api_outputs,
		tip.0,
		parent_key_id,
	)?;

	let mut heights = BTreeSet::new();
	for (commit, (id, index, _, _)) in &wallet_outputs {
		if keys::is_stateless_receive_key_id(id) {
			let height = match api_outputs.get(commit) {
				Some((_, height, _)) if *height <= tip.0 => *height,
				Some(_) => {
					return Err(Error::ClientCallback(
						"Output is above the block tip".to_owned(),
					))
				}
				None => wallet.get(id, index)?.height,
			};
			heights.insert(height);
		}
	}
	let client = wallet.w2n_client().clone();
	let previous = wallet
		.stateless_headers
		.as_ref()
		.filter(|cache| cache.node_url == client.node_url());
	let headers = resolve_stateless_headers(
		tip,
		heights,
		previous,
		|height| client.get_header_hash(height),
		|| client.get_chain_tip(),
	)?;

	apply_api_outputs(
		wallet,
		keychain_mask,
		&wallet_outputs,
		&api_outputs,
		reverted_kernels,
		stateless_sends,
		&headers,
		tip.0,
		parent_key_id,
	)?;
	if !headers.is_empty() {
		wallet.stateless_headers = Some(StatelessHeaderCache {
			node_url: client.node_url().to_owned(),
			tip: tip.clone(),
			headers,
		});
	}
	clean_old_unconfirmed(wallet, keychain_mask, tip.0)?;
	Ok(())
}

/// Check sends whose stateless inputs reappeared, and follow them until they
/// are confirmed again or cancelled. The caller verifies the chain view before
/// applying these changes alongside the stateless input observations.
fn reconcile_stateless_sends<C: NodeClient, K: Keychain>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	wallet_outputs: &HashMap<pedersen::Commitment, (Identifier, Option<u64>, Option<u32>, bool)>,
	api_outputs: &HashMap<pedersen::Commitment, (String, u64, u64)>,
	height: u64,
	parent: &Identifier,
) -> Result<Vec<(TxLogEntry, Vec<OutputData>)>, Error> {
	let mut linked = HashSet::new();
	let mut returned = HashSet::new();
	for (commit, (key, _, tx_id, _)) in wallet_outputs {
		if let Some(id) = tx_id.filter(|_| keys::is_stateless_receive_key_id(key)) {
			linked.insert(id);
			if api_outputs.contains_key(commit) {
				returned.insert(id);
			}
		}
	}
	if linked.is_empty() {
		return Ok(Vec::new());
	}

	let mut client = wallet.w2n_client().clone();
	let sends = retrieve_txs(wallet, None, None, None, Some(parent), false)?;
	let mut observations = Vec::new();
	for mut tx in sends.into_iter().filter(|tx| {
		tx.tx_type == TxLogEntryType::TxSent
			&& (if tx.confirmed {
				returned.contains(&tx.id)
			} else {
				linked.contains(&tx.id) && tx.reverted_after.is_some()
			})
	}) {
		let excess = tx.kernel_excess.ok_or_else(|| {
			Error::StoredTx("Missing kernel for stateless outgoing transaction".to_owned())
		})?;
		// A replacement branch can include the kernel below its old search bound.
		let confirmed = client.get_kernel(&excess, None, Some(height))?.is_some();
		if confirmed && tx.confirmed {
			continue;
		}
		let uuid = tx.tx_slate_id.ok_or_else(|| {
			Error::StoredTx("Missing slate ID for stateless outgoing transaction".to_owned())
		})?;
		let stored = wallet.get_stored_tx(&uuid.to_string())?.ok_or_else(|| {
			Error::StoredTx("Missing body for stateless outgoing transaction".to_owned())
		})?;
		let inputs: Vec<CommitWrapper> = stored.inputs().into();
		let inputs: HashSet<_> = inputs.iter().map(CommitWrapper::commitment).collect();
		let change: HashSet<_> = stored.outputs().iter().map(Output::commitment).collect();
		let associated = retrieve_outputs(wallet, keychain_mask, true, Some(tx.id), Some(parent))?;
		let ordinary: Vec<_> = associated
			.into_iter()
			.filter(|row| !keys::is_stateless_receive_key_id(&row.output.key_id))
			.collect();
		let live = client.get_outputs_from_node(ordinary.iter().map(|row| row.commit).collect())?;
		let mut outputs = Vec::with_capacity(ordinary.len());
		for row in ordinary {
			let mut output = row.output;
			let observation = live.get(&row.commit);
			if observation.map_or(false, |(_, observed_height, _)| *observed_height > height) {
				return Err(Error::ClientCallback(
					"Outgoing output is above the block tip".to_owned(),
				));
			}
			if inputs.contains(&row.commit) {
				output.status = if observation.is_some() {
					OutputStatus::Locked
				} else {
					OutputStatus::Spent
				};
			} else if change.contains(&row.commit) {
				output.status = match observation {
					Some((_, observed_height, _)) => {
						output.height = *observed_height;
						OutputStatus::Unspent
					}
					None if confirmed => OutputStatus::Spent,
					None => OutputStatus::Reverted,
				};
			} else {
				return Err(Error::StoredTx(
					"Unexpected output linked to stateless outgoing transaction".to_owned(),
				));
			}
			outputs.push(output);
		}
		if confirmed {
			tx.update_confirmation_ts();
			tx.reverted_after = None;
		} else if tx.confirmed {
			tx.reverted_after = Some(
				tx.confirmation_ts
					.and_then(|ts| (chrono::Utc::now() - ts).to_std().ok())
					.unwrap_or_default(),
			);
			tx.confirmation_ts = None;
		}
		tx.confirmed = confirmed;
		observations.push((tx, outputs));
	}
	Ok(observations)
}

fn find_reverted_kernels<C, K>(
	wallet: &mut WalletBackend<C, K>,
	wallet_outputs: &HashMap<pedersen::Commitment, (Identifier, Option<u64>, Option<u32>, bool)>,
	api_outputs: &HashMap<pedersen::Commitment, (String, u64, u64)>,
	parent_key_id: &Identifier,
) -> Result<HashSet<u32>, Error>
where
	C: NodeClient,
	K: Keychain,
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
	let mut bad_records = 0;
	let kernels = wallet
		.tx_log_iter()?
		.filter(|tx| {
			if tx.is_err() {
				bad_records += 1;
			}
			tx.is_ok()
		})
		.map(|t| t.unwrap())
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

	if bad_records > 0 {
		error!(
			"find_reverted_kernels: tx history is missing {} records, cause db read error",
			bad_records
		);
	}

	Ok(reverted)
}

fn clean_old_unconfirmed<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	height: u64,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	if height < 50 {
		return Ok(());
	}
	let mut ids_to_del = vec![];
	for out in wallet.iter()? {
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
pub fn retrieve_info<C, K>(
	wallet: &mut WalletBackend<C, K>,
	parent_key_id: &Identifier,
	minimum_confirmations: u64,
) -> Result<WalletInfo, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let current_height = wallet.last_confirmed_height_for_parent(parent_key_id)?;
	let outputs = wallet
		.iter()?
		.filter(|out| out.root_key_id == *parent_key_id);

	let mut unspent_total = 0;
	let mut immature_total = 0;
	let mut awaiting_finalization_total = 0;
	let mut unconfirmed_total = 0;
	let mut locked_total = 0;
	let mut reverted_total = 0;
	let mut unverified_total = 0;

	for out in outputs {
		match out.stateless_absence() {
			Some(StatelessOutputAbsence::Unverified) => {
				unverified_total += out.value;
				continue;
			}
			Some(StatelessOutputAbsence::Reverted) => {
				reverted_total += out.value;
				continue;
			}
			None => {}
		}
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
		amount_unverified: unverified_total,
	})
}

/// Build a coinbase output and insert into wallet
pub fn build_coinbase<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<CbData, Error>
where
	C: NodeClient,
	K: Keychain,
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
fn receive_coinbase<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<(Output, TxKernel, BlockFees), Error>
where
	C: NodeClient,
	K: Keychain,
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
			commit,
			value: amount,
			status: OutputStatus::Unconfirmed,
			height,
			lock_height,
			is_coinbase: true,
			tx_log_entry: None,
			stateless_origin: None,
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

#[cfg(test)]
mod stateless_header_tests {
	use super::*;

	#[test]
	fn header_cost_is_constant_on_a_known_prefix() -> Result<(), Error> {
		let heights: BTreeSet<u64> = (1..=1000).collect();
		let first_tip = (1001, "first-tip".to_owned());
		let mut calls = Vec::new();
		let headers = resolve_stateless_headers(
			&first_tip,
			heights.clone(),
			None,
			|height| {
				calls.push(height);
				Ok(Some(if height == first_tip.0 {
					first_tip.1.clone()
				} else {
					height.to_string()
				}))
			},
			|| Ok(first_tip.clone()),
		)?;
		assert_eq!(calls.len(), 1002);
		let cache = StatelessHeaderCache {
			node_url: "local".to_owned(),
			tip: first_tip.clone(),
			headers,
		};
		calls.clear();
		let next_tip = (1002, "second-tip".to_owned());
		let headers = resolve_stateless_headers(
			&next_tip,
			heights.clone(),
			Some(&cache),
			|height| {
				calls.push(height);
				Ok(Some(if height == next_tip.0 {
					next_tip.1.clone()
				} else {
					first_tip.1.clone()
				}))
			},
			|| Ok(next_tip.clone()),
		)?;
		assert_eq!(headers, cache.headers);
		assert_eq!(calls, [1002, 1001, 1002]);

		calls.clear();
		let headers = resolve_stateless_headers(
			&first_tip,
			heights.clone(),
			Some(&cache),
			|height| {
				calls.push(height);
				Ok(Some(first_tip.1.clone()))
			},
			|| Ok(first_tip.clone()),
		)?;
		assert_eq!(headers, cache.headers);
		assert_eq!(calls, [1001, 1001]);

		calls.clear();
		let fork_headers = resolve_stateless_headers(
			&next_tip,
			heights.clone(),
			Some(&cache),
			|height| {
				calls.push(height);
				Ok(Some(if height == next_tip.0 {
					next_tip.1.clone()
				} else {
					format!("fork-{}", height)
				}))
			},
			|| Ok(next_tip.clone()),
		)?;
		assert_eq!(calls.len(), 1003);
		assert_eq!(fork_headers.get(&1).map(String::as_str), Some("fork-1"));

		let unsupported = resolve_stateless_headers(
			&next_tip,
			heights.clone(),
			Some(&cache),
			|_| Ok(None),
			|| Ok(next_tip.clone()),
		)?;
		assert!(unsupported.is_empty());
		let moving = resolve_stateless_headers(
			&first_tip,
			heights,
			Some(&cache),
			|_| Ok(Some(first_tip.1.clone())),
			|| Ok(next_tip.clone()),
		);
		assert!(moving.is_err());
		Ok(())
	}
}
