// Copyright 2019 The Grin Developers
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
//! Sane serialization & deserialization of cryptographic structs into hex

use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::PublicKey;
use base64;
use serde::{Deserialize, Deserializer, Serializer};

/// Seralizes a byte string into base64
pub fn as_base64<T, S>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
where
	T: AsRef<[u8]>,
	S: Serializer,
{
	serializer.serialize_str(&base64::encode(&bytes))
}

/// Creates a RangeProof from a hex string
pub fn rangeproof_from_base64<'de, D>(deserializer: D) -> Result<RangeProof, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::{Error, IntoDeserializer};

	let val = String::deserialize(deserializer)
		.and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))?;
	RangeProof::deserialize(val.into_deserializer())
}

/// Creates a RangeProof from a hex string
pub fn commitment_from_base64<'de, D>(deserializer: D) -> Result<Commitment, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::{Error, IntoDeserializer};

	let val = String::deserialize(deserializer)
		.and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))?;
	Commitment::deserialize(val.into_deserializer())
}

/// Creates a PublicKey from a hex string
pub fn pubkey_from_base64<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::{Error, IntoDeserializer};

	let val = String::deserialize(deserializer)
		.and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))?;
	PublicKey::deserialize(val.into_deserializer())
}

/// Serializes an secp256k1 pubkey to base64
pub mod pubkey_base64 {
	use crate::grin_util::secp::PublicKey;
	use crate::grin_util::static_secp_instance;
	use base64;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let static_secp = static_secp_instance();
		let static_secp = static_secp.lock();
		serializer.serialize_str(&base64::encode(
			&key.serialize_vec(&static_secp, true).to_vec(),
		))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		let static_secp = static_secp_instance();
		let static_secp = static_secp.lock();
		String::deserialize(deserializer)
			.and_then(|string| {
				base64::decode(&string).map_err(|err| Error::custom(err.to_string()))
			})
			.and_then(|bytes: Vec<u8>| {
				PublicKey::from_slice(&static_secp, &bytes)
					.map_err(|err| Error::custom(err.to_string()))
			})
	}
}

/// Serializes an Option<secp::Signature> to and from hex
pub mod option_sig_base64 {
	use crate::grin_util::{secp, static_secp_instance};
	use base64;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(sig: &Option<secp::Signature>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let static_secp = static_secp_instance();
		let static_secp = static_secp.lock();
		match sig {
			Some(sig) => serializer.serialize_str(&base64::encode(
				&sig.serialize_compact(&static_secp).to_vec(),
			)),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<secp::Signature>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let static_secp = static_secp_instance();
		let static_secp = static_secp.lock();
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => base64::decode(&string)
				.map_err(|err| Error::custom(err.to_string()))
				.and_then(|bytes: Vec<u8>| {
					let mut b = [0u8; 64];
					b.copy_from_slice(&bytes[0..64]);
					secp::Signature::from_compact(&static_secp, &b)
						.map(Some)
						.map_err(|err| Error::custom(err.to_string()))
				}),
			None => Ok(None),
		})
	}
}

/// Serializes an Option<secp::Signature> to and from hex
pub mod option_rangeproof_base64 {
	use crate::grin_util::secp::pedersen::RangeProof;
	use base64;
	use serde::de::{Error, IntoDeserializer};
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(proof: &Option<RangeProof>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match proof {
			Some(p) => serializer.serialize_str(&base64::encode(&p)),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<RangeProof>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => base64::decode(&string)
				.map_err(|err| Error::custom(err.to_string()))
				.and_then(|val| Ok(Some(RangeProof::deserialize(val.into_deserializer())?))),
			None => Ok(None),
		})
	}
}

/// Serializes an OnionV3Address to and from hex
pub mod option_ov3_serde {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryFrom;

	use crate::util::{OnionV3Address, OnionV3AddressError};

	///
	pub fn serialize<S>(addr: &Option<OnionV3Address>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match addr {
			Some(a) => serializer.serialize_str(&a.to_string()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OnionV3Address>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(s) => OnionV3Address::try_from(s.as_str())
				.map_err(|err: OnionV3AddressError| Error::custom(format!("{:?}", err)))
				.and_then(|a| Ok(Some(a))),
			None => Ok(None),
		})
	}
}

/// Serializes an OnionV3Address to and from hex
pub mod ov3_serde {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryFrom;

	use crate::util::{OnionV3Address, OnionV3AddressError};

	///
	pub fn serialize<S>(addr: &OnionV3Address, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&addr.to_string())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<OnionV3Address, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer).and_then(|s| {
			OnionV3Address::try_from(s.as_str())
				.map_err(|err: OnionV3AddressError| Error::custom(format!("{:?}", err)))
				.and_then(Ok)
		})
	}
}

/// Serializes an ed25519 PublicKey to and from hex
pub mod dalek_pubkey_serde {
	use crate::grin_util::{from_hex, to_hex};
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(key: &DalekPublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&to_hex(key.to_bytes().to_vec()))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<DalekPublicKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| from_hex(&string).map_err(|err| Error::custom(err.to_string())))
			.and_then(|bytes: Vec<u8>| {
				DalekPublicKey::from_bytes(&bytes).map_err(|err| Error::custom(err.to_string()))
			})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_pubkey_serde {
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::grin_util::{from_hex, to_hex};

	///
	pub fn serialize<S>(key: &Option<DalekPublicKey>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&to_hex(key.to_bytes().to_vec())),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DalekPublicKey>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
				.map_err(|err| Error::custom(err.to_string()))
				.and_then(|bytes: Vec<u8>| {
					let mut b = [0u8; 32];
					b.copy_from_slice(&bytes[0..32]);
					DalekPublicKey::from_bytes(&b)
						.map(Some)
						.map_err(|err| Error::custom(err.to_string()))
				}),
			None => Ok(None),
		})
	}
}

/// Serializes an ed25519_dalek::Signature to and from hex
pub mod dalek_sig_serde {
	use ed25519_dalek::Signature as DalekSignature;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::grin_util::{from_hex, to_hex};

	///
	pub fn serialize<S>(key: &DalekSignature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&to_hex(key.to_bytes().to_vec()))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<DalekSignature, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer)
			.and_then(|string| from_hex(&string).map_err(|err| Error::custom(err.to_string())))
			.and_then(|bytes: Vec<u8>| {
				let mut b = [0u8; 64];
				b.copy_from_slice(&bytes[0..64]);
				DalekSignature::from_bytes(&b).map_err(|err| Error::custom(err.to_string()))
			})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_sig_serde {
	use ed25519_dalek::Signature as DalekSignature;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::grin_util::{from_hex, to_hex};

	///
	pub fn serialize<S>(key: &Option<DalekSignature>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&to_hex(key.to_bytes().to_vec())),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DalekSignature>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
				.map_err(|err| Error::custom(err.to_string()))
				.and_then(|bytes: Vec<u8>| {
					let mut b = [0u8; 64];
					b.copy_from_slice(&bytes[0..64]);
					DalekSignature::from_bytes(&b)
						.map(Some)
						.map_err(|err| Error::custom(err.to_string()))
				}),
			None => Ok(None),
		})
	}
}

/// Serializes slates 'version_info' field
pub mod version_info_v4 {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::slate_versions::v4::VersionCompatInfoV4;

	///
	pub fn serialize<S>(v: &VersionCompatInfoV4, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&format!("{}:{}", v.version, v.block_header_version))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<VersionCompatInfoV4, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer).and_then(|s| {
			let mut retval = VersionCompatInfoV4 {
				version: 0,
				block_header_version: 0,
			};
			let v: Vec<&str> = s.split(':').collect();
			if v.len() != 2 {
				return Err(Error::custom("Cannot parse version"));
			}
			match u16::from_str_radix(v[0], 10) {
				Ok(u) => retval.version = u,
				Err(e) => return Err(Error::custom(format!("Cannot parse version: {}", e))),
			}
			match u16::from_str_radix(v[1], 10) {
				Ok(u) => retval.block_header_version = u,
				Err(e) => return Err(Error::custom(format!("Cannot parse version: {}", e))),
			}
			Ok(retval)
		})
	}
}

// Test serialization methods of components that are being used
#[cfg(test)]
mod test {
	use super::*;
	use rand::rngs::mock::StepRng;

	use crate::grin_util::{secp, static_secp_instance};
	use ed25519_dalek::Keypair;
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use ed25519_dalek::SecretKey as DalekSecretKey;
	use ed25519_dalek::Signature as DalekSignature;
	use serde::Deserialize;

	use serde_json;

	#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
	struct SerTest {
		#[serde(with = "dalek_pubkey_serde")]
		pub pub_key: DalekPublicKey,
		#[serde(with = "option_dalek_pubkey_serde")]
		pub pub_key_opt: Option<DalekPublicKey>,
		#[serde(with = "dalek_sig_serde")]
		pub sig: DalekSignature,
		#[serde(with = "option_dalek_sig_serde")]
		pub sig_opt: Option<DalekSignature>,
	}

	impl SerTest {
		pub fn random() -> SerTest {
			let secp_inst = static_secp_instance();
			let secp = secp_inst.lock();
			let mut test_rng = StepRng::new(1234567890u64, 1);
			let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
			let d_skey = DalekSecretKey::from_bytes(&sec_key.0).unwrap();
			let d_pub_key: DalekPublicKey = (&d_skey).into();

			let keypair = Keypair {
				public: d_pub_key,
				secret: d_skey,
			};

			let d_sig = keypair.sign("test sig".as_bytes());
			println!("D sig: {:?}", d_sig);

			SerTest {
				pub_key: d_pub_key.clone(),
				pub_key_opt: Some(d_pub_key),
				sig: d_sig.clone(),
				sig_opt: Some(d_sig),
			}
		}
	}

	#[test]
	fn ser_dalek_primitives() {
		for _ in 0..10 {
			let s = SerTest::random();
			println!("Before Serialization: {:?}", s);
			let serialized = serde_json::to_string_pretty(&s).unwrap();
			println!("JSON: {}", serialized);
			let deserialized: SerTest = serde_json::from_str(&serialized).unwrap();
			println!("After Serialization: {:?}", deserialized);
			println!();
			assert_eq!(s, deserialized);
		}
	}
}
