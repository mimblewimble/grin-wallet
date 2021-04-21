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
//! Sane serialization & deserialization of cryptographic structs into hex

use serde::{Deserialize, Deserializer, Serializer};

/// Seralizes a byte string into base64
pub fn as_base64<T, S>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
where
	T: AsRef<[u8]>,
	S: Serializer,
{
	serializer.serialize_str(&base64::encode(&bytes))
}

/// Creates a Vec from a base string
pub fn bytes_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::Error;
	String::deserialize(deserializer)
		.and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))
}

/// Serializes an Option<secp::Signature> to and from hex
pub mod option_rangeproof_hex {
	use crate::grin_util::secp::pedersen::RangeProof;
	use crate::grin_util::{from_hex, ToHex};
	use serde::de::{Error, IntoDeserializer};
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(proof: &Option<RangeProof>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match proof {
			Some(p) => serializer.serialize_str(&p.to_hex()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<RangeProof>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
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
pub mod dalek_seckey_serde {
	use crate::grin_util::{from_hex, ToHex};
	use ed25519_dalek::SecretKey as DalekSecretKey;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(key: &DalekSecretKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&key.to_bytes().to_hex())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<DalekSecretKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| from_hex(&string).map_err(|err| Error::custom(err.to_string())))
			.and_then(|bytes: Vec<u8>| {
				DalekSecretKey::from_bytes(&bytes).map_err(|err| Error::custom(err.to_string()))
			})
	}
}

/// Serializes an ed25519 PublicKey to and from hex
pub mod dalek_pubkey_serde {
	use crate::grin_util::{from_hex, ToHex};
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(key: &DalekPublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&key.to_bytes().to_hex())
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

/// Serializes an x25519 PublicKey to and from hex
pub mod dalek_xpubkey_serde {
	use crate::grin_util::{from_hex, ToHex};
	use serde::{Deserialize, Deserializer, Serializer};
	use x25519_dalek::PublicKey as xDalekPublicKey;

	///
	pub fn serialize<S>(key: &xDalekPublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&key.as_bytes().to_hex())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<xDalekPublicKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| from_hex(&string).map_err(|err| Error::custom(err.to_string())))
			.and_then(|bytes: Vec<u8>| {
				let mut b = [0u8; 32];
				b.copy_from_slice(&bytes[0..32]);
				Ok(xDalekPublicKey::from(b))
			})
	}
}

/// Serializes an ed25519 PublicKey to and from base64
pub mod dalek_pubkey_base64 {
	use base64;
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(key: &DalekPublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&base64::encode(&key.to_bytes()))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<DalekPublicKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| {
				base64::decode(&string).map_err(|err| Error::custom(err.to_string()))
			})
			.and_then(|bytes: Vec<u8>| {
				DalekPublicKey::from_bytes(&bytes).map_err(|err| Error::custom(err.to_string()))
			})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_pubkey_base64 {
	use base64;
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	///
	pub fn serialize<S>(key: &Option<DalekPublicKey>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&base64::encode(&key.to_bytes())),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DalekPublicKey>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => base64::decode(&string)
				.map_err(|err| Error::custom(err.to_string()))
				.and_then(|bytes: Vec<u8>| {
					let mut b = [0u8; 32];
					b.copy_from_slice(&bytes[0..32]);
					DalekPublicKey::from_bytes(&b)
						.map(Some)
						.map_err(|err| Error::custom(err.to_string()))
				}),
			None => {
				println!("None fine");
				Ok(None)
			}
		})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_pubkey_serde {
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::grin_util::{from_hex, ToHex};

	///
	pub fn serialize<S>(key: &Option<DalekPublicKey>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&key.to_bytes().to_hex()),
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

/// Serializes an Option<x25519_dalek::PublicKey> to and from hex
pub mod option_xdalek_pubkey_serde {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};
	use x25519_dalek::PublicKey as xDalekPublicKey;

	use crate::grin_util::{from_hex, ToHex};

	///
	pub fn serialize<S>(key: &Option<xDalekPublicKey>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&key.as_bytes().to_hex()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<xDalekPublicKey>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
				.map_err(|err| Error::custom(err.to_string()))
				.and_then(|bytes: Vec<u8>| {
					let mut b = [0u8; 32];
					b.copy_from_slice(&bytes[0..32]);
					Ok(Some(xDalekPublicKey::from(b)))
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
	use std::convert::TryFrom;

	use crate::grin_util::{from_hex, ToHex};

	///
	pub fn serialize<S>(sig: &DalekSignature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&sig.to_bytes().as_ref().to_hex())
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
				DalekSignature::try_from(b).map_err(|err| Error::custom(err.to_string()))
			})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_sig_serde {
	use ed25519_dalek::Signature as DalekSignature;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryFrom;

	use crate::grin_util::{from_hex, ToHex};

	///
	pub fn serialize<S>(sig: &Option<DalekSignature>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match sig {
			Some(s) => serializer.serialize_str(&s.to_bytes().as_ref().to_hex()),
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
					DalekSignature::try_from(b)
						.map(Some)
						.map_err(|err| Error::custom(err.to_string()))
				}),
			None => Ok(None),
		})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from base64
pub mod option_dalek_sig_base64 {
	use base64;
	use ed25519_dalek::Signature as DalekSignature;
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryFrom;

	///
	pub fn serialize<S>(sig: &Option<DalekSignature>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match sig {
			Some(s) => serializer.serialize_str(&base64::encode(&s.to_bytes().to_vec())),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DalekSignature>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => base64::decode(&string)
				.map_err(|err| Error::custom(err.to_string()))
				.and_then(|bytes: Vec<u8>| {
					let mut b = [0u8; 64];
					b.copy_from_slice(&bytes[0..64]);
					DalekSignature::try_from(b)
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

/// Serializes slates 'version_info' field
pub mod version_info_v5 {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::slate_versions::v5::VersionCompatInfoV5;

	///
	pub fn serialize<S>(v: &VersionCompatInfoV5, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&format!("{}:{}", v.version, v.block_header_version))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<VersionCompatInfoV5, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer).and_then(|s| {
			let mut retval = VersionCompatInfoV5 {
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

/// Serializes slates 'state' field
pub mod slate_state_v4 {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::slate_versions::v4::SlateStateV4;

	///
	pub fn serialize<S>(st: &SlateStateV4, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let label = match st {
			SlateStateV4::Unknown => "NA",
			SlateStateV4::Standard1 => "S1",
			SlateStateV4::Standard2 => "S2",
			SlateStateV4::Standard3 => "S3",
			SlateStateV4::Invoice1 => "I1",
			SlateStateV4::Invoice2 => "I2",
			SlateStateV4::Invoice3 => "I3",
		};
		serializer.serialize_str(label)
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<SlateStateV4, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer).and_then(|s| {
			let retval = match s.as_str() {
				"NA" => SlateStateV4::Unknown,
				"S1" => SlateStateV4::Standard1,
				"S2" => SlateStateV4::Standard2,
				"S3" => SlateStateV4::Standard3,
				"I1" => SlateStateV4::Invoice1,
				"I2" => SlateStateV4::Invoice2,
				"I3" => SlateStateV4::Invoice3,
				_ => return Err(Error::custom("Invalid Slate state")),
			};
			Ok(retval)
		})
	}
}

/// Serializes slates 'state' field
pub mod slate_state_v5 {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use crate::slate_versions::v5::SlateStateV5;

	///
	pub fn serialize<S>(st: &SlateStateV5, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let label = match st {
			SlateStateV5::Unknown => "NA",
			SlateStateV5::Standard1 => "S1",
			SlateStateV5::Standard2 => "S2",
			SlateStateV5::Standard3 => "S3",
			SlateStateV5::Invoice1 => "I1",
			SlateStateV5::Invoice2 => "I2",
			SlateStateV5::Invoice3 => "I3",
			SlateStateV5::Atomic1 => "A1",
			SlateStateV5::Atomic2 => "A2",
			SlateStateV5::Atomic3 => "A3",
			SlateStateV5::Atomic4 => "A4",
			SlateStateV5::Multisig1 => "M1",
			SlateStateV5::Multisig2 => "M2",
			SlateStateV5::Multisig3 => "M3",
			SlateStateV5::Multisig4 => "M4",
		};
		serializer.serialize_str(label)
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<SlateStateV5, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer).and_then(|s| {
			let retval = match s.as_str() {
				"NA" => SlateStateV5::Unknown,
				"S1" => SlateStateV5::Standard1,
				"S2" => SlateStateV5::Standard2,
				"S3" => SlateStateV5::Standard3,
				"I1" => SlateStateV5::Invoice1,
				"I2" => SlateStateV5::Invoice2,
				"I3" => SlateStateV5::Invoice3,
				"A1" => SlateStateV5::Atomic1,
				"A2" => SlateStateV5::Atomic2,
				"A3" => SlateStateV5::Atomic3,
				"A4" => SlateStateV5::Atomic4,
				"M1" => SlateStateV5::Multisig1,
				"M2" => SlateStateV5::Multisig2,
				"M3" => SlateStateV5::Multisig3,
				"M4" => SlateStateV5::Multisig4,
				_ => return Err(Error::custom("Invalid Slate state")),
			};
			Ok(retval)
		})
	}
}

/// Serializes an secp256k1 pubkey to base64
pub mod uuid_base64 {
	use base64;
	use serde::{Deserialize, Deserializer, Serializer};
	use uuid::Uuid;

	///
	pub fn serialize<S>(id: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&base64::encode(&id.as_bytes()))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| {
				base64::decode(&string).map_err(|err| Error::custom(err.to_string()))
			})
			.and_then(|bytes: Vec<u8>| {
				let mut b = [0u8; 16];
				b.copy_from_slice(&bytes[0..16]);
				Ok(Uuid::from_bytes(b))
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
	use ed25519_dalek::Signer;
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
