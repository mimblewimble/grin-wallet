// Copyright 2021 The Grin Develope;
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

//! Functions defining wallet 'addresses', i.e. ed2559 keys based on
//! a derivation path

use crate::grin_util::secp::key::SecretKey;
use crate::Error;
use grin_keychain::{ChildNumber, Identifier, Keychain, SwitchCommitmentType};

use crate::blake2::blake2b::blake2b;

/// Derive a Slatepack address path from an output parent path and index
pub fn address_derivation_path(parent_key_id: &Identifier, index: u32) -> Identifier {
	let mut key_path = parent_key_id.to_path();
	key_path.path[1] = ChildNumber::from(1);
	key_path.depth += 1;
	key_path.path[key_path.depth as usize - 1] = ChildNumber::from(index);
	Identifier::from_path(&key_path)
}

/// Derive a secret key given a derivation path and index
pub fn address_from_derivation_path<K>(
	keychain: &K,
	parent_key_id: &Identifier,
	index: u32,
) -> Result<SecretKey, Error>
where
	K: Keychain,
{
	let key_id = address_derivation_path(parent_key_id, index);
	let sec_key = keychain.derive_key(0, &key_id, SwitchCommitmentType::None)?;
	let hashed = blake2b(32, &[], &sec_key.0[..]);
	Ok(SecretKey::from_slice(
		&keychain.secp(),
		&hashed.as_bytes()[..],
	)?)
}

#[cfg(test)]
mod tests {
	use super::*;
	use grin_keychain::ExtKeychain;

	#[test]
	fn slatepack_address_path() {
		let parent = ExtKeychain::derive_key_id(2, 2, 0, 0, 0);
		let expected = ExtKeychain::derive_key_id(3, 2, 1, 3, 0);
		assert_eq!(address_derivation_path(&parent, 3), expected);
	}
}
