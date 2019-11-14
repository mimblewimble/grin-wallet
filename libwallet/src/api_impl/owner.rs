// Copyright 2019 The Grin Develope;
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

//! Generic implementation of owner API functions

use uuid::Uuid;

use crate::grin_core::core::hash::Hashed;
use crate::grin_core::core::Transaction;
use crate::grin_core::ser;
use crate::grin_util;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;

use crate::api_impl::owner_updater::StatusMessage;
use crate::grin_keychain::{Identifier, Keychain};
use crate::internal::{keys, scan, selection, tx, updater};
use crate::slate::Slate;
use crate::types::{AcctPathMapping, NodeClient, TxLogEntry, TxWrapper, WalletBackend, WalletInfo};
use crate::{
	wallet_lock, InitTxArgs, IssueInvoiceTxArgs, NodeHeightResult, OutputCommitMapping,
	ScannedBlockInfo, TxLogEntryType, WalletInitStatus, WalletInst, WalletLCProvider,
};
use crate::{Error, ErrorKind};
use std::sync::mpsc::Sender;
use std::sync::Arc;

const USER_MESSAGE_MAX_LEN: usize = 256;

/// List of accounts
pub fn accounts<'a, T: ?Sized, C, K>(w: &mut T) -> Result<Vec<AcctPathMapping>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keys::accounts(&mut *w)
}

/// new account path
pub fn create_account_path<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keys::new_acct_path(&mut *w, keychain_mask, label)
}

/// set active account
pub fn set_active_account<'a, T: ?Sized, C, K>(w: &mut T, label: &str) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	w.set_parent_key_id_by_name(label)
}

/// retrieve outputs
pub fn retrieve_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	include_spent: bool,
	refresh_from_node: bool,
	tx_id: Option<u32>,
) -> Result<(bool, Vec<OutputCommitMapping>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut validated = false;
	if refresh_from_node {
		validated = update_wallet_state(
			wallet_inst.clone(),
			keychain_mask,
			status_send_channel,
			false,
		)?;
	}

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();

	Ok((
		validated,
		updater::retrieve_outputs(
			&mut **w,
			keychain_mask,
			include_spent,
			tx_id,
			Some(&parent_key_id),
		)?,
	))
}

/// Retrieve txs
pub fn retrieve_txs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(bool, Vec<TxLogEntry>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut validated = false;
	if refresh_from_node {
		validated = update_wallet_state(
			wallet_inst.clone(),
			keychain_mask,
			status_send_channel,
			false,
		)?;
	}

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let txs = updater::retrieve_txs(&mut **w, tx_id, tx_slate_id, Some(&parent_key_id), false)?;

	Ok((validated, txs))
}

/// Retrieve summary info
pub fn retrieve_summary_info<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	minimum_confirmations: u64,
) -> Result<(bool, WalletInfo), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut validated = false;
	if refresh_from_node {
		validated = update_wallet_state(
			wallet_inst.clone(),
			keychain_mask,
			status_send_channel,
			false,
		)?;
	}

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let wallet_info = updater::retrieve_info(&mut **w, &parent_key_id, minimum_confirmations)?;
	Ok((validated, wallet_info))
}

/// Initiate tx as sender
pub fn init_send_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: InitTxArgs,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d)?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match args.message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let mut slate = tx::new_tx_slate(&mut *w, args.amount, 2, use_test_rng)?;

	// if we just want to estimate, don't save a context, just send the results
	// back
	if let Some(true) = args.estimate_only {
		let (total, fee) = tx::estimate_send_tx(
			&mut *w,
			keychain_mask,
			args.amount,
			args.minimum_confirmations,
			args.max_outputs as usize,
			args.num_change_outputs as usize,
			args.selection_strategy_is_use_all,
			&parent_key_id,
		)?;
		slate.amount = total;
		slate.fee = fee;
		return Ok(slate);
	}

	let context = tx::add_inputs_to_slate(
		&mut *w,
		keychain_mask,
		&mut slate,
		args.minimum_confirmations,
		args.max_outputs as usize,
		args.num_change_outputs as usize,
		args.selection_strategy_is_use_all,
		&parent_key_id,
		0,
		message,
		true,
		use_test_rng,
	)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(slate.id.as_bytes(), 0, &context)?;
		batch.commit()?;
	}
	if let Some(v) = args.target_slate_version {
		slate.version_info.orig_version = v;
	}
	Ok(slate)
}

/// Initiate a transaction as the recipient (invoicing)
pub fn issue_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceTxArgs,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match args.dest_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d)?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match args.message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let mut slate = tx::new_tx_slate(&mut *w, args.amount, 2, use_test_rng)?;
	let context = tx::add_output_to_slate(
		&mut *w,
		keychain_mask,
		&mut slate,
		&parent_key_id,
		1,
		message,
		true,
		use_test_rng,
	)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(slate.id.as_bytes(), 1, &context)?;
		batch.commit()?;
	}

	if let Some(v) = args.target_slate_version {
		slate.version_info.orig_version = v;
	}

	Ok(slate)
}

/// Receive an invoice tx, essentially adding inputs to whatever
/// output was specified
pub fn process_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	args: InitTxArgs,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut ret_slate = slate.clone();
	let parent_key_id = match args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.to_owned())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};
	// Don't do this multiple times
	let tx = updater::retrieve_txs(
		&mut *w,
		None,
		Some(ret_slate.id),
		Some(&parent_key_id),
		use_test_rng,
	)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxSent {
			return Err(ErrorKind::TransactionAlreadyReceived(ret_slate.id.to_string()).into());
		}
	}

	let message = match args.message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	// update slate current height
	ret_slate.height = w.w2n_client().get_chain_tip()?.0;

	let context = tx::add_inputs_to_slate(
		&mut *w,
		keychain_mask,
		&mut ret_slate,
		args.minimum_confirmations,
		args.max_outputs as usize,
		args.num_change_outputs as usize,
		args.selection_strategy_is_use_all,
		&parent_key_id,
		0,
		message,
		false,
		use_test_rng,
	)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(slate.id.as_bytes(), 0, &context)?;
		batch.commit()?;
	}

	if let Some(v) = args.target_slate_version {
		ret_slate.version_info.orig_version = v;
	}

	Ok(ret_slate)
}

/// Lock sender outputs
pub fn tx_lock_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	participant_id: usize,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context = w.get_private_context(keychain_mask, slate.id.as_bytes(), participant_id)?;
	selection::lock_tx_context(&mut *w, keychain_mask, slate, &context)
}

/// Finalize slate
pub fn finalize_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut sl = slate.clone();
	let context = w.get_private_context(keychain_mask, sl.id.as_bytes(), 0)?;
	tx::complete_tx(&mut *w, keychain_mask, &mut sl, 0, &context)?;
	tx::update_stored_tx(&mut *w, keychain_mask, &mut sl, false)?;
	tx::update_message(&mut *w, keychain_mask, &mut sl)?;
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.delete_private_context(sl.id.as_bytes(), 0)?;
		batch.commit()?;
	}
	Ok(sl)
}

/// cancel tx
pub fn cancel_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if !update_wallet_state(
		wallet_inst.clone(),
		keychain_mask,
		status_send_channel,
		false,
	)? {
		return Err(ErrorKind::TransactionCancellationError(
			"Can't contact running Grin node. Not Cancelling.",
		))?;
	}
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	tx::cancel_tx(&mut **w, keychain_mask, &parent_key_id, tx_id, tx_slate_id)
}

/// get stored tx
pub fn get_stored_tx<'a, T: ?Sized, C, K>(
	w: &T,
	entry: &TxLogEntry,
) -> Result<Option<Transaction>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	w.get_stored_tx(entry)
}

/// Posts a transaction to the chain
/// take a client impl instead of wallet so as not to have to lock the wallet
pub fn post_tx<'a, C>(client: &C, tx: &Transaction, fluff: bool) -> Result<(), Error>
where
	C: NodeClient + 'a,
{
	let tx_hex = grin_util::to_hex(ser::ser_vec(tx, ser::ProtocolVersion(1)).unwrap());
	let res = client.post_tx(&TxWrapper { tx_hex: tx_hex }, fluff);
	if let Err(e) = res {
		error!("api: post_tx: failed with error: {}", e);
		Err(e)
	} else {
		debug!(
			"api: post_tx: successfully posted tx: {}, fluff? {}",
			tx.hash(),
			fluff
		);
		Ok(())
	}
}

/// verify slate messages
pub fn verify_slate_messages(slate: &Slate) -> Result<(), Error> {
	slate.verify_messages()
}

/// check repair
/// Accepts a wallet inst instead of a raw wallet so it can
/// lock as little as possible
pub fn scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	start_height: Option<u64>,
	delete_unconfirmed: bool,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	update_outputs(wallet_inst.clone(), keychain_mask, true)?;
	let tip = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().get_chain_tip()?
	};

	let start_height = match start_height {
		Some(h) => h,
		None => 1,
	};

	let mut info = scan::scan(
		wallet_inst.clone(),
		keychain_mask,
		delete_unconfirmed,
		start_height,
		tip.0,
		status_send_channel,
	)?;
	info.hash = tip.1;

	wallet_lock!(wallet_inst, w);
	let mut batch = w.batch(keychain_mask)?;
	batch.save_last_scanned_block(info)?;
	batch.commit()?;

	Ok(())
}

/// node height
pub fn node_height<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<NodeHeightResult, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let res = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().get_chain_tip()
	};
	match res {
		Ok(r) => Ok(NodeHeightResult {
			height: r.0,
			header_hash: r.1,
			updated_from_node: true,
		}),
		Err(_) => {
			let outputs = retrieve_outputs(wallet_inst, keychain_mask, &None, true, false, None)?;
			let height = match outputs.1.iter().map(|m| m.output.height).max() {
				Some(height) => height,
				None => 0,
			};
			Ok(NodeHeightResult {
				height,
				header_hash: "".to_owned(),
				updated_from_node: false,
			})
		}
	}
}
/// Experimental, wrap the entire definition of how a wallet's state is updated
pub fn update_wallet_state<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	update_all: bool,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = {
		wallet_lock!(wallet_inst, w);
		w.parent_key_id().clone()
	};
	let client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};

	// Step 1: Update outputs and transactions purely based on UTXO state
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::UpdatingOutputs(
			"Updating outputs from node".to_owned(),
		));
	}
	let mut result = update_outputs(wallet_inst.clone(), keychain_mask, update_all)?;

	if !result {
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::UpdateWarning(
				"Updater Thread unable to contact node".to_owned(),
			));
		}
		return Ok(result);
	}

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::UpdatingTransactions(
			"Updating transactions".to_owned(),
		));
	}

	// Step 2: Update outstanding transactions with no change outputs by kernel
	let mut txs = {
		wallet_lock!(wallet_inst, w);
		updater::retrieve_txs(&mut **w, None, None, Some(&parent_key_id), true)?
	};
	result = update_txs_via_kernel(wallet_inst.clone(), keychain_mask, &mut txs)?;
	if !result {
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::UpdateWarning(
				"Updater Thread unable to contact node".to_owned(),
			));
		}
		return Ok(result);
	}

	// Step 3: Scan back a bit on the chain
	let res = client.get_chain_tip();
	// if we can't get the tip, don't continue
	let tip = match res {
		Ok(t) => t,
		Err(_) => {
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::UpdateWarning(
					"Updater Thread unable to contact node".to_owned(),
				));
			}
			return Ok(false);
		}
	};

	// Check if this is a restored wallet that needs a full scan
	let last_scanned_block = {
		wallet_lock!(wallet_inst, w);
		match w.init_status()? {
			WalletInitStatus::InitNeedsScanning => ScannedBlockInfo {
				height: 0,
				hash: "".to_owned(),
				start_pmmr_index: 0,
				last_pmmr_index: 0,
			},
			WalletInitStatus::InitNoScanning => ScannedBlockInfo {
				height: tip.clone().0,
				hash: tip.clone().1,
				start_pmmr_index: 0,
				last_pmmr_index: 0,
			},
			WalletInitStatus::InitComplete => w.last_scanned_block()?,
		}
	};

	let start_index = last_scanned_block.height.saturating_sub(100);

	if last_scanned_block.height == 0 {
		let msg = format!("This wallet's contents has not been initialized with a full chain scan, performing scan now.
		This operation may take a while for the first scan, but should be much quicker once the initial scan is done.");
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::FullScanWarn(msg));
		}
	}

	let mut info = scan::scan(
		wallet_inst.clone(),
		keychain_mask,
		false,
		start_index,
		tip.0,
		status_send_channel,
	)?;

	info.hash = tip.1;

	wallet_lock!(wallet_inst, w);
	let mut batch = w.batch(keychain_mask)?;
	batch.save_last_scanned_block(info)?;
	// init considered complete after first successful update
	batch.save_init_status(WalletInitStatus::InitComplete)?;
	batch.commit()?;

	Ok(result)
}

/// Attempt to update outputs in wallet, return whether it was successful
fn update_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	update_all: bool,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	match updater::refresh_outputs(&mut **w, keychain_mask, &parent_key_id, update_all) {
		Ok(_) => Ok(true),
		Err(e) => {
			if let ErrorKind::InvalidKeychainMask = e.kind() {
				return Err(e);
			}
			Ok(false)
		}
	}
}

/// Update transactions that need to be validated via kernel lookup
fn update_txs_via_kernel<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	txs: &mut Vec<TxLogEntry>,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = {
		wallet_lock!(wallet_inst, w);
		w.parent_key_id().clone()
	};

	let mut client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};

	let height = match client.get_chain_tip() {
		Ok(h) => h.0,
		Err(_) => return Ok(false),
	};

	for tx in txs.iter_mut() {
		if tx.confirmed {
			continue;
		}
		if tx.amount_debited != 0 && tx.amount_credited != 0 {
			continue;
		}
		if let Some(e) = tx.kernel_excess {
			let res = client.get_kernel(&e, tx.kernel_lookup_min_height, Some(height));
			let kernel = match res {
				Ok(k) => k,
				Err(_) => return Ok(false),
			};
			if let Some(k) = kernel {
				debug!("Kernel Retrieved: {:?}", k);
				wallet_lock!(wallet_inst, w);
				let mut batch = w.batch(keychain_mask)?;
				tx.confirmed = true;
				tx.update_confirmation_ts();
				batch.save_tx_log_entry(tx.clone(), &parent_key_id)?;
				batch.commit()?;
			}
		} else {
			warn!("Attempted to update via kernel excess for transaction {:?}, but kernel excess was not stored", tx.tx_slate_id);
		}
	}
	Ok(true)
}
