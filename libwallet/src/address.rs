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

//! Functions defining wallet 'addresses', i.e. ed2559 keys based on
//! a derivation path

use crate::grin_util::secp::key::SecretKey;
use crate::Error;
use grin_wallet_util::grin_keychain::{ChildNumber, Identifier, Keychain, SwitchCommitmentType};

use crate::blake2::blake2b::blake2b;

/// Derive a secret key given a derivation path and index
pub fn address_from_derivation_path<K>(
	keychain: &K,
	parent_key_id: &Identifier,
	index: u32,
) -> Result<SecretKey, Error>
where
	K: Keychain,
{
	let mut key_path = parent_key_id.to_path();
	// An output derivation for acct m/0
	// is m/0/0/0, m/0/0/1 (for instance), m/1 is m/1/0/0, m/1/0/1
	// Address generation path should be
	// for m/0: m/0/1/0, m/0/1/1
	// for m/1: m/1/1/0, m/1/1/1
	key_path.path[1] = ChildNumber::from(1);
	key_path.depth += 1;
	key_path.path[key_path.depth as usize - 1] = ChildNumber::from(index);
	let key_id = Identifier::from_path(&key_path);
	let sec_key = keychain.derive_key(0, &key_id, SwitchCommitmentType::None)?;
	let hashed = blake2b(32, &[], &sec_key.0[..]);
	Ok(SecretKey::from_slice(
		&keychain.secp(),
		&hashed.as_bytes()[..],
	)?)
}
