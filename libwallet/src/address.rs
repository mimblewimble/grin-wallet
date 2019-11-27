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
use crate::{Error, ErrorKind};
use grin_wallet_util::grin_keychain::{ChildNumber, Identifier, Keychain, SwitchCommitmentType};

use data_encoding::BASE32;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use failure::ResultExt;
use sha3::{Digest, Sha3_256};

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
	key_path.depth = key_path.depth + 1;
	key_path.path[key_path.depth as usize - 1] = ChildNumber::from(index);
	let key_id = Identifier::from_path(&key_path);
	let sec_key = keychain.derive_key(0, &key_id, &SwitchCommitmentType::None)?;
	let hashed = blake2b(32, &[], &sec_key.0[..]);
	Ok(SecretKey::from_slice(
		&keychain.secp(),
		&hashed.as_bytes()[..],
	)?)
}

/// Output ed25519 keypair given an rust_secp256k1 SecretKey
pub fn ed25519_keypair(sec_key: &SecretKey) -> Result<(DalekSecretKey, DalekPublicKey), Error> {
	let d_skey = match DalekSecretKey::from_bytes(&sec_key.0) {
		Ok(k) => k,
		Err(e) => {
			return Err(ErrorKind::ED25519Key(format!("{}", e)).to_owned())?;
		}
	};
	let d_pub_key: DalekPublicKey = (&d_skey).into();
	Ok((d_skey, d_pub_key))
}

/// Return the ed25519 public key represented in an onion address
pub fn pubkey_from_onion_v3(onion_address: &str) -> Result<DalekPublicKey, Error> {
	let mut input = onion_address.to_uppercase();
	if input.starts_with("HTTP://") || input.starts_with("HTTPS://") {
		input = input.replace("HTTP://", "");
		input = input.replace("HTTPS://", "");
	}
	if input.ends_with(".ONION") {
		input = input.replace(".ONION", "");
	}
	let orig_address_raw = input.clone();
	// for now, just check input is the right length and try and decode from base32
	if input.len() != 56 {
		return Err(
			ErrorKind::AddressDecoding("Input address is wrong length".to_owned()).to_owned(),
		)?;
	}
	let mut address = BASE32
		.decode(input.as_bytes())
		.context(ErrorKind::AddressDecoding(
			"Input address is not base 32".to_owned(),
		))?
		.to_vec();

	address.split_off(32);
	let key = match DalekPublicKey::from_bytes(&address) {
		Ok(k) => k,
		Err(_) => {
			return Err(ErrorKind::AddressDecoding(
				"Provided onion V3 address is invalid (parsing key)".to_owned(),
			)
			.to_owned())?;
		}
	};
	let test_v3 = match onion_v3_from_pubkey(&key) {
		Ok(k) => k,
		Err(_) => {
			return Err(ErrorKind::AddressDecoding(
				"Provided onion V3 address is invalid (converting from pubkey)".to_owned(),
			)
			.to_owned())?;
		}
	};

	if test_v3.to_uppercase() != orig_address_raw.to_uppercase() {
		return Err(ErrorKind::AddressDecoding(
			"Provided onion V3 address is invalid (no match)".to_owned(),
		)
		.to_owned())?;
	}
	Ok(key)
}

/// Generate an onion address from an ed25519_dalek public key
pub fn onion_v3_from_pubkey(pub_key: &DalekPublicKey) -> Result<String, Error> {
	// calculate checksum
	let mut hasher = Sha3_256::new();
	hasher.input(b".onion checksum");
	hasher.input(pub_key.as_bytes());
	hasher.input([0x03u8]);
	let checksum = hasher.result();

	let mut address_bytes = pub_key.as_bytes().to_vec();
	address_bytes.push(checksum[0]);
	address_bytes.push(checksum[1]);
	address_bytes.push(0x03u8);

	let ret = BASE32.encode(&address_bytes);
	Ok(ret.to_lowercase())
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn onion_v3_conversion() {
		let onion_address = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";

		let key = pubkey_from_onion_v3(onion_address).unwrap();
		println!("Key: {:?}", &key);

		let out_address = onion_v3_from_pubkey(&key).unwrap();
		println!("Address: {:?}", &out_address);

		assert_eq!(onion_address, out_address);
	}
}
