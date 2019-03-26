// Copyright 2018 The Grin Developers
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

use crate::grin_keychain::{Identifier, Keychain};
use crate::internal::{keys, selection, tx, updater};
use crate::slate::Slate;
use crate::types::{
	AcctPathMapping, NodeClient, OutputCommitMapping, TxEstimation, TxLogEntry, TxWrapper,
	WalletBackend, WalletInfo,
};
use crate::{Error, ErrorKind};

const USER_MESSAGE_MAX_LEN: usize = 256;

/// List of accounts
pub fn accounts<T: ?Sized, C, K>(w: &mut T) -> Result<Vec<AcctPathMapping>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	keys::accounts(&mut *w)
}

/// new account path
pub fn create_account_path<T: ?Sized, C, K>(w: &mut T, label: &str) -> Result<Identifier, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	keys::new_acct_path(&mut *w, label)
}

/// set active account
pub fn set_active_account<T: ?Sized, C, K>(w: &mut T, label: &str) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	w.set_parent_key_id_by_name(label)
}

/// retrieve outputs
pub fn retrieve_outputs<T: ?Sized, C, K>(
	w: &mut T,
	include_spent: bool,
	refresh_from_node: bool,
	tx_id: Option<u32>,
) -> Result<(bool, Vec<OutputCommitMapping>), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = w.parent_key_id();

	let mut validated = false;
	if refresh_from_node {
		validated = update_outputs(w, false);
	}

	Ok((
		validated,
		updater::retrieve_outputs(&mut *w, include_spent, tx_id, Some(&parent_key_id))?,
	))
}

/// Retrieve txs
pub fn retrieve_txs<T: ?Sized, C, K>(
	w: &mut T,
	refresh_from_node: bool,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(bool, Vec<TxLogEntry>), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = w.parent_key_id();

	let mut validated = false;
	if refresh_from_node {
		validated = update_outputs(w, false);
	}

	Ok((
		validated,
		updater::retrieve_txs(&mut *w, tx_id, tx_slate_id, Some(&parent_key_id), false)?,
	))
}

/// Retrieve summary info
pub fn retrieve_summary_info<T: ?Sized, C, K>(
	w: &mut T,
	refresh_from_node: bool,
	minimum_confirmations: u64,
) -> Result<(bool, WalletInfo), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = w.parent_key_id();

	let mut validated = false;
	if refresh_from_node {
		validated = update_outputs(w, false);
	}

	let wallet_info = updater::retrieve_info(&mut *w, &parent_key_id, minimum_confirmations)?;
	Ok((validated, wallet_info))
}

/// Initiate tx as sender
pub fn initiate_tx<T: ?Sized, C, K>(
	w: &mut T,
	src_acct_name: Option<&str>,
	amount: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
	message: Option<String>,
	target_slate_version: Option<u16>,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = match src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.to_owned())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let mut slate = tx::new_tx_slate(&mut *w, amount, 2, use_test_rng)?;

	let context = tx::add_inputs_to_slate(
		&mut *w,
		&mut slate,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
		0,
		message,
		use_test_rng,
	)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch()?;
		batch.save_private_context(slate.id.as_bytes(), &context)?;
		batch.commit()?;
	}
	if let Some(v) = target_slate_version {
		slate.version_info.orig_version = v;
	}
	Ok(slate)
}

/// Estimate
pub fn estimate_initiate_tx<T: ?Sized, C, K>(
	w: &mut T,
	src_acct_name: Option<&str>,
	amount: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
) -> Result<TxEstimation, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = match src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.to_owned())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};
	let (total, fee) = tx::estimate_send_tx(
		&mut *w,
		amount,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
	)?;
	Ok(TxEstimation { total, fee })
}

/// Lock sender outputs
pub fn tx_lock_outputs<T: ?Sized, C, K>(w: &mut T, slate: &Slate) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let context = w.get_private_context(slate.id.as_bytes())?;
	selection::lock_tx_context(&mut *w, slate, &context)
}

/// Finalize slate
pub fn finalize_tx<T: ?Sized, C, K>(w: &mut T, slate: &Slate) -> Result<Slate, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut sl = slate.clone();
	let context = w.get_private_context(sl.id.as_bytes())?;
	tx::complete_tx(&mut *w, &mut sl, 0, &context)?;
	tx::update_stored_tx(&mut *w, &mut sl)?;
	tx::update_message(&mut *w, &mut sl)?;
	{
		let mut batch = w.batch()?;
		batch.delete_private_context(sl.id.as_bytes())?;
		batch.commit()?;
	}
	Ok(sl)
}

/// cancel tx
pub fn cancel_tx<T: ?Sized, C, K>(
	w: &mut T,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = w.parent_key_id();
	if !update_outputs(w, false) {
		return Err(ErrorKind::TransactionCancellationError(
			"Can't contact running Grin node. Not Cancelling.",
		))?;
	}
	tx::cancel_tx(&mut *w, &parent_key_id, tx_id, tx_slate_id)
}

/// get stored tx
pub fn get_stored_tx<T: ?Sized, C, K>(
	w: &T,
	entry: &TxLogEntry,
) -> Result<Option<Transaction>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	w.get_stored_tx(entry)
}

/// Posts a transaction to the chain
/// take a client impl instead of wallet so as not to have to lock the wallet
pub fn post_tx<C>(client: &C, tx: &Transaction, fluff: bool) -> Result<(), Error>
where
	C: NodeClient,
{
	let tx_hex = grin_util::to_hex(ser::ser_vec(tx).unwrap());
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

/// Attempt to restore contents of wallet
pub fn restore<T: ?Sized, C, K>(w: &mut T) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	w.restore()
}

/// check repair
pub fn check_repair<T: ?Sized, C, K>(w: &mut T, delete_unconfirmed: bool) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	update_outputs(w, true);
	w.check_repair(delete_unconfirmed)
}

/// node height
pub fn node_height<T: ?Sized, C, K>(w: &mut T) -> Result<(u64, bool), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let res = w.w2n_client().get_chain_height();
	match res {
		Ok(height) => Ok((height, true)),
		Err(_) => {
			let outputs = retrieve_outputs(w, true, false, None)?;
			let height = match outputs.1.iter().map(|m| m.output.height).max() {
				Some(height) => height,
				None => 0,
			};
			Ok((height, false))
		}
	}
}

/// Attempt to update outputs in wallet, return whether it was successful
fn update_outputs<T: ?Sized, C, K>(w: &mut T, update_all: bool) -> bool
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = w.parent_key_id();
	match updater::refresh_outputs(&mut *w, &parent_key_id, update_all) {
		Ok(_) => true,
		Err(_) => false,
	}
}
