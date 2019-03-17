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

use crate::internal::{tx, updater};
use crate::keychain::Keychain;
use crate::slate::Slate;
use crate::types::{BlockFees, CbData, NodeClient, TxLogEntryType, WalletBackend};
use crate::{Error, ErrorKind};

const USER_MESSAGE_MAX_LEN: usize = 256;

/// Build a coinbase transaction
pub fn build_coinbase<T: ?Sized, C, K>(w: &mut T, block_fees: &BlockFees) -> Result<CbData, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	updater::build_coinbase(&mut *w, block_fees)
}

/// verify slate messages
pub fn verify_slate_messages(slate: &Slate) -> Result<(), Error> {
	slate.verify_messages()
}

/// Receive a tx as recipient
pub fn receive_tx<T: ?Sized, C, K>(
	w: &mut T,
	slate: &mut Slate,
	dest_acct_name: Option<&str>,
	message: Option<String>,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
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
	let tx = updater::retrieve_txs(&mut *w, None, Some(slate.id), Some(&parent_key_id), false)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxReceived {
			return Err(ErrorKind::TransactionAlreadyReceived(slate.id.to_string()).into());
		}
	}

	let message = match message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	tx::add_output_to_slate(&mut *w, slate, &parent_key_id, 1, message)?;
	tx::update_message(&mut *w, slate)?;
	Ok(())
}
