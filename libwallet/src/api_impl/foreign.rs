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
use strum::IntoEnumIterator;

use crate::grin_keychain::Keychain;
use crate::internal::{tx, updater};
use crate::slate_versions::SlateVersion;
use crate::{
	BlockFees, CbData, Error, ErrorKind, NodeClient, Slate, TxLogEntryType, VersionInfo,
	WalletBackend,
};

const FOREIGN_API_VERSION: u16 = 2;
const USER_MESSAGE_MAX_LEN: usize = 256;

/// Return the version info
pub fn check_version() -> VersionInfo {
	VersionInfo {
		foreign_api_version: FOREIGN_API_VERSION,
		supported_slate_versions: SlateVersion::iter().collect(),
	}
}

/// Build a coinbase transaction
pub fn build_coinbase<T: ?Sized, C, K>(
	w: &mut T,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<CbData, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	updater::build_coinbase(&mut *w, block_fees, test_mode)
}

/// verify slate messages
pub fn verify_slate_messages(slate: &Slate) -> Result<(), Error> {
	slate.verify_messages()
}

/// Receive a tx as recipient
pub fn receive_tx<T: ?Sized, C, K>(
	w: &mut T,
	slate: &Slate,
	dest_acct_name: Option<&str>,
	message: Option<String>,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut ret_slate = slate.clone();
	let parent_key_id = match dest_acct_name {
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
		if t.tx_type == TxLogEntryType::TxReceived {
			return Err(ErrorKind::TransactionAlreadyReceived(ret_slate.id.to_string()).into());
		}
	}

	let message = match message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	tx::add_output_to_slate(
		&mut *w,
		&mut ret_slate,
		&parent_key_id,
		1,
		message,
		false,
		use_test_rng,
	)?;
	tx::update_message(&mut *w, &mut ret_slate)?;
	Ok(ret_slate)
}

/// Receive an tx that this wallet has issued
pub fn finalize_invoice_tx<T: ?Sized, C, K>(w: &mut T, slate: &Slate) -> Result<Slate, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut sl = slate.clone();
	let context = w.get_private_context(sl.id.as_bytes(), 1)?;
	tx::complete_tx(&mut *w, &mut sl, 1, &context)?;
	tx::update_stored_tx(&mut *w, &mut sl, true)?;
	tx::update_message(&mut *w, &mut sl)?;
	{
		let mut batch = w.batch()?;
		batch.delete_private_context(sl.id.as_bytes(), 1)?;
		batch.commit()?;
	}
	Ok(sl)
}
