// Copyright 2023 The Grin Developers
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

//! Dalek key wrapper for mwixnet primitives

use grin_util::secp::key::SecretKey;

use ed25519_dalek::{PublicKey, Signature, Verifier};
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use grin_util::ToHex;
use thiserror::Error;

/// Error types for Dalek structures and logic
#[derive(Clone, Error, Debug, PartialEq)]
pub enum DalekError {
	/// Hex deser error
	#[error("Hex error {0:?}")]
	HexError(String),
	/// Key parsing error
	#[error("Failed to parse secret key")]
	KeyParseError,
	/// Error validating signature
	#[error("Failed to verify signature")]
	SigVerifyFailed,
}

/// Encapsulates an ed25519_dalek::PublicKey and provides (de-)serialization
#[derive(Clone, Debug, PartialEq)]
pub struct DalekPublicKey(PublicKey);

impl DalekPublicKey {
	/// Convert DalekPublicKey to hex string
	pub fn to_hex(&self) -> String {
		self.0.to_hex()
	}

	/// Convert hex string to DalekPublicKey.
	pub fn from_hex(hex: &str) -> Result<Self, DalekError> {
		let bytes = grin_util::from_hex(hex)
			.map_err(|_| DalekError::HexError(format!("failed to decode {}", hex)))?;
		let pk = PublicKey::from_bytes(bytes.as_ref())
			.map_err(|_| DalekError::HexError(format!("failed to decode {}", hex)))?;
		Ok(DalekPublicKey(pk))
	}

	/// Compute DalekPublicKey from a SecretKey
	pub fn from_secret(key: &SecretKey) -> Self {
		let secret = ed25519_dalek::SecretKey::from_bytes(&key.0).unwrap();
		let pk: PublicKey = (&secret).into();
		DalekPublicKey(pk)
	}
}

impl AsRef<PublicKey> for DalekPublicKey {
	fn as_ref(&self) -> &PublicKey {
		&self.0
	}
}

#[cfg(test)]
/// Serializes an Option<DalekPublicKey> to and from hex
pub mod option_dalek_pubkey_serde {
	use super::DalekPublicKey;
	use grin_util::ToHex;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(pk: &Option<DalekPublicKey>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match pk {
			Some(pk) => serializer.serialize_str(&pk.0.to_hex()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DalekPublicKey>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => DalekPublicKey::from_hex(&string)
				.map_err(|e| Error::custom(e.to_string()))
				.and_then(|pk: DalekPublicKey| Ok(Some(pk))),
			None => Ok(None),
		})
	}
}

impl Readable for DalekPublicKey {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let pk = PublicKey::from_bytes(&reader.read_fixed_bytes(32)?)
			.map_err(|_| ser::Error::CorruptedData)?;
		Ok(DalekPublicKey(pk))
	}
}

impl Writeable for DalekPublicKey {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.0.to_bytes())?;
		Ok(())
	}
}

/// Encapsulates an ed25519_dalek::Signature and provides (de-)serialization
#[derive(Clone, Debug, PartialEq)]
pub struct DalekSignature(Signature);

impl DalekSignature {
	/// Convert hex string to DalekSignature.
	#[allow(dead_code)]
	pub fn from_hex(hex: &str) -> Result<Self, DalekError> {
		let bytes = grin_util::from_hex(hex)
			.map_err(|_| DalekError::HexError(format!("failed to decode {}", hex)))?;
		let sig = Signature::from_bytes(bytes.as_ref())
			.map_err(|_| DalekError::HexError(format!("failed to decode {}", hex)))?;
		Ok(DalekSignature(sig))
	}

	/// Verifies DalekSignature
	#[allow(dead_code)]
	pub fn verify(&self, pk: &DalekPublicKey, msg: &[u8]) -> Result<(), DalekError> {
		pk.as_ref()
			.verify(&msg, &self.0)
			.map_err(|_| DalekError::SigVerifyFailed)
	}
}

impl AsRef<Signature> for DalekSignature {
	fn as_ref(&self) -> &Signature {
		&self.0
	}
}

/// Serializes a DalekSignature to and from hex
#[cfg(test)]
pub mod dalek_sig_serde {
	use super::DalekSignature;
	use grin_util::ToHex;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(sig: &DalekSignature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&sig.0.to_hex())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<DalekSignature, D::Error>
	where
		D: Deserializer<'de>,
	{
		let str = String::deserialize(deserializer)?;
		let sig = DalekSignature::from_hex(&str).map_err(|e| Error::custom(e.to_string()))?;
		Ok(sig)
	}
}

/// Dalek signature sign wrapper
// TODO: This is likely duplicated throughout crate, check
#[cfg(test)]
pub fn sign(sk: &SecretKey, message: &[u8]) -> Result<DalekSignature, DalekError> {
	use ed25519_dalek::{Keypair, Signer};
	let secret =
		ed25519_dalek::SecretKey::from_bytes(&sk.0).map_err(|_| DalekError::KeyParseError)?;
	let public: PublicKey = (&secret).into();
	let keypair = Keypair { secret, public };
	let sig = keypair.sign(&message);
	Ok(DalekSignature(sig))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mwixnet::onion::test_util::rand_keypair;
	use grin_core::ser::{self, ProtocolVersion};
	use grin_util::ToHex;
	use rand::Rng;
	use serde::{Deserialize, Serialize};
	use serde_json::Value;

	#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
	struct TestPubKeySerde {
		#[serde(with = "option_dalek_pubkey_serde", default)]
		pk: Option<DalekPublicKey>,
	}

	#[test]
	fn pubkey_test() -> Result<(), Box<dyn std::error::Error>> {
		// Test from_hex
		let rand_pk = rand_keypair().1;
		let pk_from_hex = DalekPublicKey::from_hex(rand_pk.0.to_hex().as_str()).unwrap();
		assert_eq!(rand_pk.0, pk_from_hex.0);

		// Test ser (de-)serialization
		let bytes = ser::ser_vec(&rand_pk, ProtocolVersion::local()).unwrap();
		assert_eq!(bytes.len(), 32);
		let pk_from_deser: DalekPublicKey = ser::deserialize_default(&mut &bytes[..]).unwrap();
		assert_eq!(rand_pk.0, pk_from_deser.0);

		// Test serde with Some(rand_pk)
		let some = TestPubKeySerde {
			pk: Some(rand_pk.clone()),
		};
		let val = serde_json::to_value(some.clone()).unwrap();
		if let Value::Object(o) = &val {
			if let Value::String(s) = o.get("pk").unwrap() {
				assert_eq!(s, &rand_pk.0.to_hex());
			} else {
				panic!("Invalid type");
			}
		} else {
			panic!("Invalid type")
		}
		assert_eq!(some, serde_json::from_value(val).unwrap());

		// Test serde with empty pk field
		let none = TestPubKeySerde { pk: None };
		let val = serde_json::to_value(none.clone()).unwrap();
		if let Value::Object(o) = &val {
			if let Value::Null = o.get("pk").unwrap() {
				// ok
			} else {
				panic!("Invalid type");
			}
		} else {
			panic!("Invalid type")
		}
		assert_eq!(none, serde_json::from_value(val).unwrap());

		// Test serde with no pk field
		let none2 = serde_json::from_str::<TestPubKeySerde>("{}").unwrap();
		assert_eq!(none, none2);

		Ok(())
	}

	#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
	struct TestSigSerde {
		#[serde(with = "dalek_sig_serde")]
		sig: DalekSignature,
	}

	#[test]
	fn sig_test() -> Result<(), Box<dyn std::error::Error>> {
		// Sign a message
		let (sk, pk) = rand_keypair();
		let msg: [u8; 16] = rand::thread_rng().gen();
		let sig = sign(&sk, &msg).unwrap();

		// Verify signature
		assert!(sig.verify(&pk, &msg).is_ok());

		// Wrong message
		let wrong_msg: [u8; 16] = rand::thread_rng().gen();
		assert!(sig.verify(&pk, &wrong_msg).is_err());

		// Wrong pubkey
		let wrong_pk = rand_keypair().1;
		assert!(sig.verify(&wrong_pk, &msg).is_err());

		// Test from_hex
		let sig_from_hex = DalekSignature::from_hex(sig.0.to_hex().as_str()).unwrap();
		assert_eq!(sig.0, sig_from_hex.0);

		// Test serde (de-)serialization
		let serde_test = TestSigSerde { sig: sig.clone() };
		let val = serde_json::to_value(serde_test.clone()).unwrap();
		if let Value::Object(o) = &val {
			if let Value::String(s) = o.get("sig").unwrap() {
				assert_eq!(s, &sig.0.to_hex());
			} else {
				panic!("Invalid type");
			}
		} else {
			panic!("Invalid type")
		}
		assert_eq!(serde_test, serde_json::from_value(val).unwrap());

		Ok(())
	}
}
