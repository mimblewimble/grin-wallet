// Copyright 2024 The Grin Developers
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

//! Types related to mwixnet requests required by rest of lib crate apis
//! Should rexport all needed types here

use super::onion::comsig_serde;
use grin_core::libtx::secp_ser::string_or_u64;
use grin_util::secp::key::SecretKey;
use grin_util::ToHex;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey, StaticSecret};

pub use super::onion::{onion::Onion, ComSignature, Hop};

/// A Swap request
#[derive(Serialize, Deserialize, Debug)]
pub struct SwapReq {
	/// Com signature
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
	/// Onion
	pub onion: Onion,
}

/// Public X25519 key of an mwixnet server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MwixnetServerPublicKey([u8; 32]);

impl MwixnetServerPublicKey {
	/// Derive the public key published by an mwixnet server.
	pub fn from_secret(key: &SecretKey) -> Self {
		let key = PublicKey::from(&StaticSecret::from(key.0));
		Self(key.to_bytes())
	}

	/// Parse a public key from hexadecimal representation.
	pub fn from_hex(value: &str) -> Result<Self, String> {
		let bytes = grin_util::from_hex(value).map_err(|e| e.to_string())?;
		let bytes: [u8; 32] = bytes
			.try_into()
			.map_err(|_| "mwixnet server public key must be 32 bytes".to_string())?;
		Ok(Self(bytes))
	}

	/// Return the public key bytes.
	pub fn to_bytes(self) -> [u8; 32] {
		self.0
	}

	/// Return the hexadecimal representation.
	pub fn to_hex(self) -> String {
		self.0.to_hex()
	}
}

impl Serialize for MwixnetServerPublicKey {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_hex())
	}
}

impl<'de> Deserialize<'de> for MwixnetServerPublicKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		Self::from_hex(&value).map_err(D::Error::custom)
	}
}

/// mwixnetRequest Creation Params
#[derive(Serialize, Deserialize, Debug)]
pub struct MixnetReqCreationParams {
	/// Public keys of all participating servers
	pub server_keys: Vec<MwixnetServerPublicKey>,
	/// Fees per hop
	#[serde(with = "string_or_u64")]
	pub fee_per_hop: u64,
}
