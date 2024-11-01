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

//! Onion defn for mwixnet

use super::util::{read_optional, vec_to_array, write_optional};

use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::result::Result;

use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use grin_core::core::FeeFields;
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use grin_util::secp::{
	self as secp256k1zkp,
	key::SecretKey,
	pedersen::{Commitment, RangeProof},
};
use grin_util::{self, ToHex};
use hmac::digest::InvalidLength;
use hmac::{Hmac, Mac};
use serde::ser::SerializeStruct;
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as xPublicKey, SharedSecret, StaticSecret};

use super::crypto::secp;

type HmacSha256 = Hmac<Sha256>;
/// Raw bytes alias
pub type RawBytes = Vec<u8>;

const CURRENT_ONION_VERSION: u8 = 0;

/// A data packet with layers of encryption
#[derive(Clone, Debug)]
pub struct Onion {
	/// The onion originator's portion of the shared secret
	pub ephemeral_pubkey: xPublicKey,
	/// The pedersen commitment before adjusting the excess and subtracting the fee
	pub commit: Commitment,
	/// The encrypted payloads which represent the layers of the onion
	pub enc_payloads: Vec<RawBytes>,
}

impl PartialEq for Onion {
	fn eq(&self, other: &Onion) -> bool {
		*self.ephemeral_pubkey.as_bytes() == *other.ephemeral_pubkey.as_bytes()
			&& self.commit == other.commit
			&& self.enc_payloads == other.enc_payloads
	}
}

impl Eq for Onion {}

impl Hash for Onion {
	fn hash<H: Hasher>(&self, state: &mut H) {
		state.write(self.ephemeral_pubkey.as_bytes());
		state.write(self.commit.as_ref());
		state.write_usize(self.enc_payloads.len());
		for p in &self.enc_payloads {
			state.write(p.as_slice());
		}
	}
}

/// A single, decrypted/peeled layer of an Onion.
#[derive(Debug, Clone)]
pub struct Payload {
	/// PK of next server
	pub next_ephemeral_pk: xPublicKey,
	/// Excess calculation
	pub excess: SecretKey,
	/// Fee
	pub fee: FeeFields,
	/// Rangeproof
	pub rangeproof: Option<RangeProof>,
}

impl Payload {
	/// Deserialize
	pub fn deserialize(bytes: &Vec<u8>) -> Result<Payload, ser::Error> {
		let payload: Payload = ser::deserialize_default(&mut &bytes[..])?;
		Ok(payload)
	}

	/// Serialize
	pub fn serialize(&self) -> Result<Vec<u8>, ser::Error> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &self)?;
		Ok(vec)
	}
}

impl Readable for Payload {
	fn read<R: Reader>(reader: &mut R) -> Result<Payload, ser::Error> {
		let version = reader.read_u8()?;
		if version != CURRENT_ONION_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}

		let next_ephemeral_pk =
			xPublicKey::from(vec_to_array::<32>(&reader.read_fixed_bytes(32)?)?);
		let excess = secp::read_secret_key(reader)?;
		let fee = FeeFields::try_from(reader.read_u64()?).map_err(|_| ser::Error::CorruptedData)?;
		let rangeproof = read_optional(reader)?;
		Ok(Payload {
			next_ephemeral_pk,
			excess,
			fee,
			rangeproof,
		})
	}
}

impl Writeable for Payload {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(CURRENT_ONION_VERSION)?;
		writer.write_fixed_bytes(&self.next_ephemeral_pk.as_bytes())?;
		writer.write_fixed_bytes(&self.excess)?;
		writer.write_u64(self.fee.into())?;
		write_optional(writer, &self.rangeproof)?;
		Ok(())
	}
}

/// An onion with a layer decrypted
#[derive(Clone, Debug)]
pub struct PeeledOnion {
	/// The payload from the peeled layer
	pub payload: Payload,
	/// The onion remaining after a layer was peeled
	pub onion: Onion,
}

impl Onion {
	/// Serialize to binary
	pub fn serialize(&self) -> Result<Vec<u8>, ser::Error> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &self)?;
		Ok(vec)
	}

	/// Peel a single layer off of the Onion, returning the peeled Onion and decrypted Payload
	pub fn peel_layer(&self, server_key: &SecretKey) -> Result<PeeledOnion, OnionError> {
		let shared_secret = StaticSecret::from(server_key.0).diffie_hellman(&self.ephemeral_pubkey);
		let mut cipher = new_stream_cipher(&shared_secret)?;

		let mut decrypted_bytes = self.enc_payloads[0].clone();
		cipher.apply_keystream(&mut decrypted_bytes);
		let decrypted_payload = Payload::deserialize(&decrypted_bytes)
			.map_err(|e| OnionError::DeserializationError(e))?;

		let enc_payloads: Vec<RawBytes> = self
			.enc_payloads
			.iter()
			.enumerate()
			.filter(|&(i, _)| i != 0)
			.map(|(_, enc_payload)| {
				let mut p = enc_payload.clone();
				cipher.apply_keystream(&mut p);
				p
			})
			.collect();

		let mut commitment = self.commit.clone();
		commitment = secp::add_excess(&commitment, &decrypted_payload.excess)
			.map_err(|e| OnionError::CalcCommitError(e))?;
		commitment = secp::sub_value(&commitment, decrypted_payload.fee.into())
			.map_err(|e| OnionError::CalcCommitError(e))?;

		let peeled_onion = Onion {
			ephemeral_pubkey: decrypted_payload.next_ephemeral_pk,
			commit: commitment.clone(),
			enc_payloads,
		};
		Ok(PeeledOnion {
			payload: decrypted_payload,
			onion: peeled_onion,
		})
	}
}

/// Create a new stream cipher
pub fn new_stream_cipher(shared_secret: &SharedSecret) -> Result<ChaCha20, OnionError> {
	let mut mu_hmac = HmacSha256::new_from_slice(b"MWIXNET")?;
	mu_hmac.update(shared_secret.as_bytes());
	let mukey = mu_hmac.finalize().into_bytes();

	let key = Key::from_slice(&mukey[0..32]);
	let nonce = Nonce::from_slice(b"NONCE1234567");

	Ok(ChaCha20::new(&key, &nonce))
}

impl Writeable for Onion {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.ephemeral_pubkey.as_bytes())?;
		writer.write_fixed_bytes(&self.commit)?;
		writer.write_u64(self.enc_payloads.len() as u64)?;
		for p in &self.enc_payloads {
			writer.write_u64(p.len() as u64)?;
			p.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for Onion {
	fn read<R: Reader>(reader: &mut R) -> Result<Onion, ser::Error> {
		let pubkey_bytes: [u8; 32] = vec_to_array(&reader.read_fixed_bytes(32)?)?;
		let ephemeral_pubkey = xPublicKey::from(pubkey_bytes);
		let commit = Commitment::read(reader)?;
		let mut enc_payloads: Vec<RawBytes> = Vec::new();
		let len = reader.read_u64()?;
		for _ in 0..len {
			let size = reader.read_u64()?;
			let bytes = reader.read_fixed_bytes(size as usize)?;
			enc_payloads.push(bytes);
		}
		Ok(Onion {
			ephemeral_pubkey,
			commit,
			enc_payloads,
		})
	}
}

impl serde::ser::Serialize for Onion {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::ser::Serializer,
	{
		let mut state = serializer.serialize_struct("Onion", 3)?;

		state.serialize_field("pubkey", &self.ephemeral_pubkey.as_bytes().to_hex())?;
		state.serialize_field("commit", &self.commit.to_hex())?;

		let hex_payloads: Vec<String> = self.enc_payloads.iter().map(|v| v.to_hex()).collect();
		state.serialize_field("data", &hex_payloads)?;
		state.end()
	}
}

impl<'de> serde::de::Deserialize<'de> for Onion {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::de::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		#[serde(field_identifier, rename_all = "snake_case")]
		enum Field {
			Pubkey,
			Commit,
			Data,
		}

		struct OnionVisitor;

		impl<'de> serde::de::Visitor<'de> for OnionVisitor {
			type Value = Onion;

			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str("an Onion")
			}

			fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
			where
				A: serde::de::MapAccess<'de>,
			{
				let mut pubkey = None;
				let mut commit = None;
				let mut data = None;

				while let Some(key) = map.next_key()? {
					match key {
						Field::Pubkey => {
							let val: String = map.next_value()?;
							let vec =
								grin_util::from_hex(&val).map_err(serde::de::Error::custom)?;
							pubkey =
								Some(xPublicKey::from(vec_to_array::<32>(&vec).map_err(
									|_| serde::de::Error::custom("Invalid length pubkey"),
								)?));
						}
						Field::Commit => {
							let val: String = map.next_value()?;
							let vec =
								grin_util::from_hex(&val).map_err(serde::de::Error::custom)?;
							commit = Some(Commitment::from_vec(vec));
						}
						Field::Data => {
							let val: Vec<String> = map.next_value()?;
							let mut vec: Vec<Vec<u8>> = Vec::new();
							for hex in val {
								vec.push(
									grin_util::from_hex(&hex).map_err(serde::de::Error::custom)?,
								);
							}
							data = Some(vec);
						}
					}
				}

				Ok(Onion {
					ephemeral_pubkey: pubkey.unwrap(),
					commit: commit.unwrap(),
					enc_payloads: data.unwrap(),
				})
			}
		}

		const FIELDS: &[&str] = &["pubkey", "commit", "data"];
		deserializer.deserialize_struct("Onion", &FIELDS, OnionVisitor)
	}
}

/// Error types for creating and peeling Onions
#[derive(Clone, Error, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OnionError {
	/// Invalid Key Length
	#[error("Invalid key length for MAC initialization")]
	InvalidKeyLength,
	/// Serialization Error
	#[error("Serialization error occurred: {0:?}")]
	SerializationError(ser::Error),
	/// Deserialization Error
	#[error("Deserialization error occurred: {0:?}")]
	DeserializationError(ser::Error),
	/// Error calculating blinding factor
	#[error("Error calculating blinding factor: {0:?}")]
	CalcBlindError(secp256k1zkp::Error),
	/// Error calculating ephemeral pubkey
	#[error("Error calculating ephemeral pubkey: {0:?}")]
	CalcPubKeyError(secp256k1zkp::Error),
	/// Error calculating commit
	#[error("Error calculating commitment: {0:?}")]
	CalcCommitError(secp256k1zkp::Error),
}

impl From<InvalidLength> for OnionError {
	fn from(_err: InvalidLength) -> OnionError {
		OnionError::InvalidKeyLength
	}
}

impl From<ser::Error> for OnionError {
	fn from(err: ser::Error) -> OnionError {
		OnionError::SerializationError(err)
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use crate::mwixnet::onion::crypto::secp::random_secret;
	use crate::mwixnet::onion::{new_hop, Hop};

	use grin_core::core::FeeFields;

	/// Test end-to-end Onion creation and unwrapping logic.
	#[test]
	fn onion() {
		let total_fee: u64 = 10;
		let fee_per_hop: u32 = 2;
		let in_value: u64 = 1000;
		let out_value: u64 = in_value - total_fee;
		let blind = random_secret(false);
		let commitment = secp::commit(in_value, &blind).unwrap();

		let mut hops: Vec<Hop> = Vec::new();
		let mut keys: Vec<SecretKey> = Vec::new();
		let mut final_commit = secp::commit(out_value, &blind).unwrap();
		let mut final_blind = blind.clone();
		for i in 0..5 {
			keys.push(random_secret(false));

			let excess = random_secret(false);

			let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
			final_blind.add_assign(&secp, &excess).unwrap();
			final_commit = secp::add_excess(&final_commit, &excess).unwrap();
			let proof = if i == 4 {
				let n1 = random_secret(false);
				let rp = secp.bullet_proof(
					out_value,
					final_blind.clone(),
					n1.clone(),
					n1.clone(),
					None,
					None,
				);
				assert!(secp.verify_bullet_proof(final_commit, rp, None).is_ok());
				Some(rp)
			} else {
				None
			};

			let hop = new_hop(&keys[i], &excess, fee_per_hop, proof);
			hops.push(hop);
		}

		let mut onion_packet =
			crate::mwixnet::onion::create_onion(&commitment, &hops, false).unwrap();

		let mut payload = Payload {
			next_ephemeral_pk: onion_packet.ephemeral_pubkey.clone(),
			excess: random_secret(false),
			fee: FeeFields::from(fee_per_hop),
			rangeproof: None,
		};
		for i in 0..5 {
			let peeled = onion_packet.peel_layer(&keys[i]).unwrap();
			payload = peeled.payload;
			onion_packet = peeled.onion;
		}

		assert!(payload.rangeproof.is_some());
		assert_eq!(payload.rangeproof.unwrap(), hops[4].rangeproof.unwrap());
		assert_eq!(secp::commit(out_value, &final_blind).unwrap(), final_commit);
		assert_eq!(payload.fee, FeeFields::from(fee_per_hop));
	}
}
