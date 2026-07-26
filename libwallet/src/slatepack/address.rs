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

use bech32::{self, FromBase32, ToBase32};
use ed25519_dalek::SigningKey as edDalekSecretKey;
/// Slatepack Address definition
use ed25519_dalek::VerifyingKey as edDalekPublicKey;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::PublicKey as xDalekPublicKey;

use crate::grin_core::global;
use crate::grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use crate::grin_util::secp::key::SecretKey;
use crate::util::OnionV3Address;
use crate::Error;

use std::convert::TryFrom;
use std::fmt::{self, Display};

/// Definition of a Slatepack address
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlatepackAddress {
	/// Human-readable prefix
	pub hrp: String,
	/// ed25519 Public key, to be bech32 encoded,
	/// interpreted as tor address or converted
	/// to an X25519 public key for encrypting
	/// slatepacks
	pub pub_key: edDalekPublicKey,
}

fn slatepack_hrp() -> &'static str {
	match global::get_chain_type() {
		global::ChainTypes::Mainnet => "grin",
		_ => "tgrin",
	}
}

impl SlatepackAddress {
	/// new with default hrp
	pub fn new(pub_key: &edDalekPublicKey) -> Self {
		Self {
			hrp: String::from(slatepack_hrp()),
			pub_key: pub_key.clone(),
		}
	}

	/// new with a random key
	pub fn random() -> Self {
		let bytes: [u8; 32] = thread_rng().gen();
		let pub_key = edDalekPublicKey::from(&edDalekSecretKey::from_bytes(&bytes));
		SlatepackAddress::new(&pub_key)
	}

	/// calculate encoded length
	pub fn encoded_len(&self) -> Result<usize, Error> {
		let encoded = String::try_from(self)?;
		// add length byte
		Ok(encoded.as_bytes().len() + 1)
	}

	/// utility to construct a public key that can be read by age 0.5+,
	/// for some reason the author decided the library can no longer accept
	/// x25519 keys to construct its types even though it uses them under the hood
	pub fn to_age_pubkey_str(&self) -> Result<String, Error> {
		let x_key = xDalekPublicKey::try_from(self)?;
		Ok(bech32::encode("age", x_key.as_bytes().to_base32())?.to_string())
	}

	/// Check if address network is valid.
	pub fn valid_network(&self) -> bool {
		valid_network(&self.hrp)
	}
}

impl Display for SlatepackAddress {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		match String::try_from(self) {
			Ok(encoded) => formatter.write_str(&encoded),
			Err(_) => formatter.write_str("<invalid Slatepack address>"),
		}
	}
}

impl TryFrom<&str> for SlatepackAddress {
	type Error = Error;
	fn try_from(encoded: &str) -> Result<Self, Self::Error> {
		let (hrp, data) = bech32::decode(&encoded)?;
		if !valid_network(&hrp) {
			return Err(Error::SlatepackAddress(format!(
				"wrong address prefix for chain {:?}",
				global::get_chain_type()
			)));
		}
		let bytes = Vec::<u8>::from_base32(&data)?;
		let b = <&[u8; 32]>::try_from(bytes.as_slice())
			.map_err(|_| Error::SlatepackAddress("Wrong encoded data".to_string()))?;
		let pub_key = match edDalekPublicKey::from_bytes(&b) {
			Ok(k) => k,
			Err(e) => {
				return Err(Error::ED25519Key(format!("{}", e)));
			}
		};
		Ok(SlatepackAddress { hrp, pub_key })
	}
}

impl TryFrom<&SlatepackAddress> for String {
	type Error = Error;
	fn try_from(addr: &SlatepackAddress) -> Result<Self, Self::Error> {
		let encoded = bech32::encode(&addr.hrp, addr.pub_key.to_bytes().to_base32())?;
		Ok(encoded.to_string())
	}
}

impl From<&SlatepackAddress> for OnionV3Address {
	fn from(addr: &SlatepackAddress) -> Self {
		OnionV3Address::from_bytes(addr.pub_key.to_bytes())
	}
}

impl TryFrom<OnionV3Address> for SlatepackAddress {
	type Error = Error;
	fn try_from(addr: OnionV3Address) -> Result<SlatepackAddress, Error> {
		Ok(SlatepackAddress::new(&addr.to_ed25519()?))
	}
}

impl TryFrom<&SlatepackAddress> for xDalekPublicKey {
	type Error = Error;
	fn try_from(addr: &SlatepackAddress) -> Result<Self, Self::Error> {
		let cep =
			curve25519_dalek::edwards::CompressedEdwardsY::from_slice(addr.pub_key.as_bytes());
		let ep = match cep
			.map_err(|e| Error::ED25519Key(format!("{}", e)))?
			.decompress()
		{
			Some(p) => p,
			None => {
				return Err(Error::ED25519Key(
					"Can't decompress ed25519 Edwards Point".into(),
				));
			}
		};
		let res = xDalekPublicKey::from(ep.to_montgomery().to_bytes());
		Ok(res)
	}
}

impl TryFrom<&SecretKey> for SlatepackAddress {
	type Error = Error;
	fn try_from(key: &SecretKey) -> Result<Self, Self::Error> {
		let d_skey = edDalekSecretKey::from_bytes(&key.0);
		let d_pub_key: edDalekPublicKey = (&d_skey).into();
		Ok(Self::new(&d_pub_key))
	}
}

/// Serializes a SlatepackAddress to a bech32 string
impl Serialize for SlatepackAddress {
	///
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(
			&String::try_from(self).map_err(|err| serde::ser::Error::custom(err.to_string()))?,
		)
	}
}

/// Deserialize from a bech32 string
impl<'de> Deserialize<'de> for SlatepackAddress {
	fn deserialize<D>(deserializer: D) -> Result<SlatepackAddress, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct SlatepackAddressVisitor;

		impl<'de> serde::de::Visitor<'de> for SlatepackAddressVisitor {
			type Value = SlatepackAddress;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(formatter, "a SlatepackAddress")
			}

			fn visit_str<E>(self, value: &str) -> Result<SlatepackAddress, E>
			where
				E: serde::de::Error,
			{
				let s = SlatepackAddress::try_from(value)
					.map_err(|err| serde::de::Error::custom(err.to_string()))?;
				Ok(s)
			}
		}

		deserializer.deserialize_str(SlatepackAddressVisitor)
	}
}

/// write binary trait
impl Writeable for SlatepackAddress {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// We're actually going to encode the bech32 address as opposed to
		// the binary serialization
		let encoded = match String::try_from(self) {
			Ok(e) => e,
			Err(e) => {
				error!("Cannot parse Slatepack address: {:?}, {}", self, e);
				return Err(ser::Error::CorruptedData);
			}
		};
		// write length, max 255
		let bytes = encoded.as_bytes();
		if bytes.len() > 255 {
			error!(
				"Cannot encode Slatepackaddress: {:?}, Too Long (Max 255)",
				self
			);
			return Err(ser::Error::CorruptedData);
		}
		writer.write_u8(bytes.len() as u8)?;
		writer.write_fixed_bytes(&bytes)
	}
}

impl Readable for SlatepackAddress {
	fn read<R: Reader>(reader: &mut R) -> Result<SlatepackAddress, ser::Error> {
		// read length as u8
		let len = reader.read_u8()?;
		// and bech32 string
		let encoded = match String::from_utf8(reader.read_fixed_bytes(len as usize)?) {
			Ok(a) => a,
			Err(e) => {
				error!("Cannot parse Slatepack address from utf8: {}", e);
				return Err(ser::Error::CorruptedData);
			}
		};
		let parsed_addr = match SlatepackAddress::try_from(encoded.as_str()) {
			Ok(a) => a,
			Err(e) => {
				error!("Cannot parse Slatepack address: {}, {}", encoded, e);
				return Err(ser::Error::CorruptedData);
			}
		};
		Ok(parsed_addr)
	}
}

/// Check if encoded HRP is for valid network.
fn valid_network(hrp: &str) -> bool {
	slatepack_hrp() == hrp
}

#[test]
fn slatepack_address() -> Result<(), Error> {
	use rand::{thread_rng, Rng};
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

	// Check validation.
	let bytes: [u8; 32] = thread_rng().gen();
	let pub_key = edDalekPublicKey::from(&edDalekSecretKey::from_bytes(&bytes));
	let wrong_net_addr = SlatepackAddress {
		hrp: "grin".to_string(),
		pub_key,
	};
	assert!(!wrong_net_addr.valid_network());
	let right_addr = SlatepackAddress {
		hrp: "tgrin".to_string(),
		pub_key,
	};
	assert!(right_addr.valid_network());
	let invalid_addr = SlatepackAddress {
		hrp: "invalid hrp".to_string(),
		pub_key,
	};
	assert!(!invalid_addr.valid_network());
	assert_eq!(invalid_addr.to_string(), "<invalid Slatepack address>");

	let valid_addr = "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp";
	let parsed_valid_addr = SlatepackAddress::try_from(valid_addr);
	assert!(parsed_valid_addr.is_ok());

	let valid_addr2 = "TGRIN1XTXAVWFGS48CKF3GK8WWGCNDMN0NT4TVKL8A7LTYEJJCY2MC6NFS9GM2LP";
	let parsed_valid_addr2 = SlatepackAddress::try_from(valid_addr2);
	assert!(parsed_valid_addr2.is_ok());

	let invalid_addr = "slatepack10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqnlumr7";
	let parsed_invalid_addr = SlatepackAddress::try_from(invalid_addr);
	assert!(parsed_invalid_addr.is_err());

	let wrong_net_addr = "grin1dvge9z4uqgqlpspmljrd7smh3grrw9xu2r9lkz3u67s3emj3ud2sd5gk9p";
	let parsed_wrong_net_addr = SlatepackAddress::try_from(wrong_net_addr);
	assert!(parsed_wrong_net_addr.is_err());

	let sec_key_bytes: [u8; 32] = thread_rng().gen();

	let ed_sec_key = edDalekSecretKey::from_bytes(&sec_key_bytes);
	let ed_pub_key = edDalekPublicKey::from(&ed_sec_key);
	let addr = SlatepackAddress::new(&ed_pub_key);
	let x_pub_key = xDalekPublicKey::try_from(&addr)?;

	let x_dec_secret = x25519_dalek::StaticSecret::from(sec_key_bytes);
	let x_pub_key_direct = xDalekPublicKey::from(&x_dec_secret);

	println!("ed sec key: {:?}", ed_sec_key);
	println!("ed pub key: {:?}", ed_pub_key);
	println!("x pub key from addr: {:?}", x_pub_key);
	println!("x pub key direct: {:?}", x_pub_key_direct);

	let encoded = String::try_from(&addr).unwrap();
	println!("Encoded bech32: {}", encoded);
	let parsed_addr = SlatepackAddress::try_from(encoded.as_str()).unwrap();
	assert_eq!(addr, parsed_addr);

	// ensure ed25519 pub keys and x25519 pubkeys are equivalent on decryption
	let mut slatepack = super::Slatepack::default();
	let mut payload: Vec<u8> = Vec::with_capacity(243);
	for _ in 0..payload.capacity() {
		payload.push(rand::random());
	}
	slatepack.payload = payload;
	let orig_sp = slatepack.clone();

	slatepack.try_encrypt_payload(vec![addr.clone()])?;
	slatepack.try_decrypt_payload(Some(&ed_sec_key))?;

	assert_eq!(orig_sp.payload, slatepack.payload);

	Ok(())
}
