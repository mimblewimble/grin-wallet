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

use crate::grin_util::from_hex;
use data_encoding::BASE32;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// OnionV3 Address Errors
pub enum OnionV3Error {
	/// Error decoding an address from a string
	AddressDecoding(String),
	/// Error with given private key
	InvalidPrivateKey(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Struct to hold an onion V3 address, represented internally as a raw
/// ed25519 public key
pub struct OnionV3Address([u8; 32]);

impl OnionV3Address {
	/// from bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		OnionV3Address(bytes)
	}

	/// as bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// populate from a private key
	pub fn from_private(key: &[u8; 32]) -> Result<Self, OnionV3Error> {
		let d_skey = match DalekSecretKey::from_bytes(key) {
			Ok(k) => k,
			Err(e) => {
				return Err(OnionV3Error::InvalidPrivateKey(format!(
					"Unable to create public key: {}",
					e
				)));
			}
		};
		let d_pub_key: DalekPublicKey = (&d_skey).into();
		Ok(OnionV3Address(*d_pub_key.as_bytes()))
	}

	/// return dalek public key
	pub fn to_ed25519(&self) -> Result<DalekPublicKey, OnionV3Error> {
		let d_skey = match DalekPublicKey::from_bytes(&self.0) {
			Ok(k) => k,
			Err(e) => {
				return Err(OnionV3Error::InvalidPrivateKey(format!(
					"Unable to create dalek public key: {}",
					e
				)));
			}
		};
		Ok(d_skey)
	}

	/// Return as onion v3 address string
	fn to_ov3_str(&self) -> String {
		// calculate checksum
		let mut hasher = Sha3_256::new();
		hasher.input(b".onion checksum");
		hasher.input(self.0);
		hasher.input([0x03u8]);
		let checksum = hasher.result();

		let mut address_bytes = self.0.to_vec();
		address_bytes.push(checksum[0]);
		address_bytes.push(checksum[1]);
		address_bytes.push(0x03u8);

		let ret = BASE32.encode(&address_bytes);
		ret.to_lowercase()
	}
}

impl fmt::Display for OnionV3Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.to_ov3_str())
	}
}

impl TryFrom<&str> for OnionV3Address {
	type Error = OnionV3Error;

	fn try_from(input: &str) -> Result<Self, Self::Error> {
		// First attempt to decode a pubkey from hex
		if let Ok(b) = from_hex(input) {
			if b.len() == 32 {
				let mut retval = OnionV3Address([0; 32]);
				retval.0.copy_from_slice(&b[0..32]);
				return Ok(retval);
			} else {
				return Err(OnionV3Error::AddressDecoding(
					"(Interpreted as Hex String) Public key is wrong length".to_owned(),
				));
			}
		};

		// Otherwise try to parse as onion V3 address
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
				"(Interpreted as Base32 String) Input address is wrong length".to_owned(),
			));
		}
		let address = match BASE32.decode(input.as_bytes()) {
			Ok(a) => a,
			Err(_) => {
				return Err(OnionV3Error::AddressDecoding(
					"(Interpreted as Base32 String) Input address is not base 32".to_owned(),
				));
			}
		};

		let mut retval = OnionV3Address([0; 32]);
		retval.0.copy_from_slice(&address[0..32]);

		let test_v3 = retval.to_ov3_str();
		if test_v3.to_uppercase() != orig_address_raw.to_uppercase() {
			return Err(OnionV3Error::AddressDecoding(
				"(Interpreted as Base32 String) Provided onion V3 address is invalid (no match)"
					.to_owned(),
			));
		}

		Ok(retval)
	}
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
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";
		let onion_address_2: OnionV3Address = raw_pubkey_str.try_into()?;

		assert_eq!(onion_address, onion_address_2);

		// invalid hex string, should be interpreted as base32 and fail
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bx";
		let ret: Result<OnionV3Address, OnionV3Error> = raw_pubkey_str.try_into();
		assert!(ret.is_err());

		// wrong length hex string, should be interpreted as base32 and fail
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bbff";
		let ret: Result<OnionV3Address, OnionV3Error> = raw_pubkey_str.try_into();
		assert!(ret.is_err());

		// wrong length ov3 string
		let onion_address_str = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyidx";
		let ret: Result<OnionV3Address, OnionV3Error> = onion_address_str.try_into();
		assert!(ret.is_err());

		// not base 32 ov3 string
		let onion_address_str = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyi-";
		let ret: Result<OnionV3Address, OnionV3Error> = onion_address_str.try_into();
		assert!(ret.is_err());

		Ok(())
	}
}
