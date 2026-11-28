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
use crate::error::Error;
use crate::grin_keychain::{ExtKeychain, Identifier, Keychain};
use crate::grin_util::secp::key::SecretKey;
use crate::types::{AcctPathMapping, NodeClient};
use crate::WalletBackend;
use rand::rngs::mock::StepRng;
use rand::{thread_rng, Rng};

/// Marker bit set on the second path element of every key derived for a
/// stateless receive. Regular wallet keys live at `m/a/0/n` (depth 3), so a
/// depth 4 path whose second element carries this bit can never collide with
/// them.
pub const STATELESS_RECEIVE_MARKER: u32 = 0x4000_0000;

/// Number of random bits placed below the marker in the second path element.
pub const STATELESS_RECEIVE_R0_BITS: u32 = 27;

const STATELESS_RECEIVE_R0_MASK: u32 = (1 << STATELESS_RECEIVE_R0_BITS) - 1;
const NON_HARDENED_MASK: u32 = 0x7fff_ffff;

/// Returns the account index `a` if `parent_key_id` is a regular account
/// path of the form `m/a/0`.
fn account_index(parent_key_id: &Identifier) -> Option<u32> {
	let p = parent_key_id.to_path();
	if p.depth == 2 && <u32>::from(p.path[1]) == 0 {
		Some(<u32>::from(p.path[0]))
	} else {
		None
	}
}

/// Derive a fresh output key id for a stateless receive into the account at
/// `parent_key_id`.
///
/// The key lives at `m/a/(0x40000000 | r0)/r1/r2`, where `r0` is 27 random
/// bits and `r1`, `r2` are 31 random bits each (89 bits in total). Nothing is
/// read from or written to the wallet database: the path is committed to in
/// the output's rewindable range proof, which is how a later scan recognises
/// the output and recovers its key.
pub fn stateless_receive_key_id(
	parent_key_id: &Identifier,
	use_test_rng: bool,
) -> Result<Identifier, Error> {
	let acct = account_index(parent_key_id).ok_or_else(|| {
		Error::GenericError(format!(
			"Stateless receive requires an account path of the form m/a/0, got {}",
			parent_key_id.to_bip_32_string()
		))
	})?;
	let (r0, r1, r2): (u32, u32, u32) = match use_test_rng {
		false => {
			let mut rng = thread_rng();
			(rng.gen(), rng.gen(), rng.gen())
		}
		true => {
			// allow for consistent test results
			let mut rng = StepRng::new(1_234_567_892_u64, 1);
			(rng.gen(), rng.gen(), rng.gen())
		}
	};
	Ok(ExtKeychain::derive_key_id(
		4,
		acct,
		STATELESS_RECEIVE_MARKER | (r0 & STATELESS_RECEIVE_R0_MASK),
		r1 & NON_HARDENED_MASK,
		r2 & NON_HARDENED_MASK,
	))
}

/// Whether `key_id` is a key derived by [`stateless_receive_key_id`].
pub fn is_stateless_receive_key_id(key_id: &Identifier) -> bool {
	let p = key_id.to_path();
	let d1 = <u32>::from(p.path[1]);
	p.depth == 4
		&& d1 & !STATELESS_RECEIVE_R0_MASK == STATELESS_RECEIVE_MARKER
		&& <u32>::from(p.path[2]) & !NON_HARDENED_MASK == 0
		&& <u32>::from(p.path[3]) & !NON_HARDENED_MASK == 0
}

/// The account (parent) path an output key belongs to.
///
/// For regular keys this is the BIP32 parent. Keys derived for a stateless
/// receive sit two levels below a random intermediate path, so their BIP32
/// parent is meaningless to the wallet; they belong to the account `m/a/0`
/// they were received into.
pub fn output_parent_key_id(key_id: &Identifier) -> Identifier {
	if is_stateless_receive_key_id(key_id) {
		let acct = <u32>::from(key_id.to_path().path[0]);
		ExtKeychain::derive_key_id(2, acct, 0, 0, 0)
	} else {
		key_id.parent_path()
	}
}

/// Get next available key in the wallet for a given parent
pub fn next_available_key<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
) -> Result<Identifier, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let child = wallet.next_child(keychain_mask)?;
	Ok(child)
}

/// Retrieve an existing key from a wallet
pub fn retrieve_existing_key<C, K>(
	wallet: &WalletBackend<C, K>,
	key_id: Identifier,
	mmr_index: Option<u64>,
) -> Result<(Identifier, u32), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let existing = wallet.get(&key_id, &mmr_index)?;
	let key_id = existing.key_id.clone();
	let derivation = existing.n_child;
	Ok((key_id, derivation))
}

/// Returns a list of account to BIP32 path mappings
pub fn accounts<C, K>(wallet: &WalletBackend<C, K>) -> Result<Vec<AcctPathMapping>, Error>
where
	C: NodeClient,
	K: Keychain,
{
	Ok(wallet.acct_path_iter()?.collect())
}

/// Adds a new parent account path with a given label
pub fn new_acct_path<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let label = label.to_owned();
	if wallet.acct_path_iter()?.any(|l| l.label == label) {
		return Err(Error::AccountLabelAlreadyExists(label));
	}

	// We're always using paths at m/k/0 for parent keys for output derivations
	// so find the highest of those, then increment (to conform with external/internal
	// derivation chains in BIP32 spec)

	let highest_entry = wallet.acct_path_iter()?.max_by(|a, b| {
		<u32>::from(a.path.to_path().path[0]).cmp(&<u32>::from(b.path.to_path().path[0]))
	});

	let next_account = match highest_entry {
		Some(entry) => u32::from(entry.path.to_path().path[0])
			.checked_add(1)
			.ok_or_else(|| {
				Error::Backend("Wallet account derivation index exhausted".to_owned())
			})?,
		None => 0,
	};
	let return_id = ExtKeychain::derive_key_id(2, next_account, 0, 0, 0);

	let save_path = AcctPathMapping {
		label,
		path: return_id.clone(),
	};

	let mut batch = wallet.batch(keychain_mask)?;
	batch.save_acct_path(save_path)?;
	batch.commit()?;
	Ok(return_id)
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn stateless_receive_key_ids() {
		for acct in [0u32, 1, 7] {
			let parent = ExtKeychain::derive_key_id(2, acct, 0, 0, 0);
			let a = stateless_receive_key_id(&parent, false).unwrap();
			let b = stateless_receive_key_id(&parent, false).unwrap();
			assert_ne!(a, b);
			for id in [a, b] {
				let p = id.to_path();
				assert_eq!(p.depth, 4);
				assert_eq!(<u32>::from(p.path[0]), acct);
				assert_eq!(
					<u32>::from(p.path[1]) >> STATELESS_RECEIVE_R0_BITS,
					STATELESS_RECEIVE_MARKER >> STATELESS_RECEIVE_R0_BITS
				);
				assert!(is_stateless_receive_key_id(&id));
				assert_eq!(output_parent_key_id(&id), parent);
			}
		}
	}

	#[test]
	fn regular_key_ids_are_not_stateless() {
		let parent = ExtKeychain::derive_key_id(2, 3, 0, 0, 0);
		let child = ExtKeychain::derive_key_id(3, 3, 0, 42, 0);
		assert!(!is_stateless_receive_key_id(&parent));
		assert!(!is_stateless_receive_key_id(&child));
		assert_eq!(output_parent_key_id(&child), parent);
		// depth 4 without the marker, or with unexpected high bits, is left alone
		let no_marker = ExtKeychain::derive_key_id(4, 3, 5, 6, 7);
		assert!(!is_stateless_receive_key_id(&no_marker));
		assert_eq!(output_parent_key_id(&no_marker), no_marker.parent_path());
		let hardened = ExtKeychain::derive_key_id(4, 3, 0xc000_0001, 6, 7);
		assert!(!is_stateless_receive_key_id(&hardened));
		let wide = ExtKeychain::derive_key_id(4, 3, 0x4800_0000, 6, 7);
		assert!(!is_stateless_receive_key_id(&wide));
	}

	#[test]
	fn stateless_receive_needs_an_account_path() {
		let child = ExtKeychain::derive_key_id(3, 0, 0, 1, 0);
		assert!(stateless_receive_key_id(&child, false).is_err());
	}
}
