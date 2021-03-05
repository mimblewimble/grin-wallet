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

//! Wallet key management functions
use crate::error::{Error, ErrorKind};
use crate::grin_keychain::{ChildNumber, ExtKeychain, Identifier, Keychain};
use crate::grin_util::secp::key::SecretKey;
use crate::types::{AcctPathMapping, NodeClient, WalletBackend};

/// Get next available key in the wallet for a given parent
pub fn next_available_key<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let child = wallet.next_child(keychain_mask)?;
	Ok(child)
}

/// Retrieve an existing key from a wallet
pub fn retrieve_existing_key<'a, T: ?Sized, C, K>(
	wallet: &T,
	key_id: Identifier,
	mmr_index: Option<u64>,
) -> Result<(Identifier, u32), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let existing = wallet.get(&key_id, &mmr_index)?;
	let key_id = existing.key_id.clone();
	let derivation = existing.n_child;
	Ok((key_id, derivation))
}

/// Returns a list of account to BIP32 path mappings
pub fn accounts<'a, T: ?Sized, C, K>(wallet: &mut T) -> Result<Vec<AcctPathMapping>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	Ok(wallet.acct_path_iter().collect())
}

/// Adds an new parent account path with a given label
pub fn new_acct_path<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let label = label.to_owned();
	if wallet.acct_path_iter().any(|l| l.label == label) {
		return Err(ErrorKind::AccountLabelAlreadyExists(label).into());
	}

	// We're always using paths at m/k/0 for parent keys for output derivations
	// so find the highest of those, then increment (to conform with external/internal
	// derivation chains in BIP32 spec)

	let highest_entry = wallet.acct_path_iter().max_by(|a, b| {
		<u32>::from(a.path.to_path().path[0]).cmp(&<u32>::from(b.path.to_path().path[0]))
	});

	let return_id = {
		if let Some(e) = highest_entry {
			let mut p = e.path.to_path();
			p.path[0] = ChildNumber::from(<u32>::from(p.path[0]) + 1);
			p.to_identifier()
		} else {
			ExtKeychain::derive_key_id(2, 0, 0, 0, 0)
		}
	};

	let save_path = AcctPathMapping {
		label: label,
		path: return_id.clone(),
	};

	let mut batch = wallet.batch(keychain_mask)?;
	batch.save_acct_path(save_path)?;
	batch.commit()?;
	Ok(return_id)
}

/// Adds/sets a particular account path with a given label
pub fn set_acct_path<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	label: &str,
	path: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let label = label.to_owned();
	let save_path = AcctPathMapping {
		label: label,
		path: path.clone(),
	};

	let mut batch = wallet.batch(keychain_mask)?;
	batch.save_acct_path(save_path)?;
	batch.commit()?;
	Ok(())
}
