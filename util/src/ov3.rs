// Copyright 2020 The Grin Developers
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
use data_encoding::BASE32;
use ed25519_dalek::PublicKey as DalekPubKey;
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub enum OnionV3Error {
	AddressDecoding(String),
}

#[derive(Debug, Clone)]
/// Struct to hold an onion V3 address, represented internally as a raw
/// ed25519 public key
pub struct OnionV3Address([u8; 32]);

impl OnionV3Address {}

impl TryFrom<&str> for OnionV3Address {
	type Error = OnionV3Error;

	fn try_from(input: &str) -> Result<Self, Self::Error> {
		let mut input = input.to_uppercase();
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
			return Err(OnionV3Error::AddressDecoding(
				"Input address is wrong length".to_owned(),
			));
		}
		let mut address = match BASE32.decode(input.as_bytes()) {
			Ok(a) => a,
			Err(_) => {
				return Err(OnionV3Error::AddressDecoding(
					"Input address is not base 32".to_owned(),
				));
			}
		};

		address.split_off(32);
		let key = match DalekPubKey::from_bytes(&address) {
			Ok(k) => k,
			Err(_) => {
				return Err(OnionV3Error::AddressDecoding(
					"Provided onion V3 address is invalid (parsing key)".to_owned(),
				))
			}
		};

		let test_v3 = onion_v3_from_pubkey(&key);
		if test_v3.to_uppercase() != orig_address_raw.to_uppercase() {
			return Err(OnionV3Error::AddressDecoding(
				"Provided onion V3 address is invalid (no match)".to_owned(),
			));
		}
		let mut retval = OnionV3Address([0; 32]);
		retval.0.copy_from_slice(&address[0..32]);

		Ok(retval)
	}
}

/// Generate an onion address from an ed25519_dalek public key
fn onion_v3_from_pubkey(pub_key: &DalekPubKey) -> String {
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
	ret.to_lowercase()
}

#[cfg(test)]
mod test {
	use super::*;
	use std::convert::TryInto;

	#[test]
	fn onion_v3() -> Result<(), OnionV3Error> {
		let onion_address_str = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";
		let onion_address: OnionV3Address = onion_address_str.try_into()?;

		println!("Onion address: {:?}", onion_address);

		/*let key = pubkey_from_onion_v3(onion_address).unwrap();
		println!("Key: {:?}", &key);

		let out_address = onion_v3_from_pubkey(&key).unwrap();
		println!("Address: {:?}", &out_address);

		assert_eq!(onion_address, out_address);*/
		Ok(())
	}
}
