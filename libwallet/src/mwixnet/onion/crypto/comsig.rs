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

//! Comsig modules for mxmixnet

use grin_util::secp::{
	self as secp256k1zkp, pedersen::Commitment, rand::thread_rng, ContextFlag, Secp256k1, SecretKey,
};

use blake2_rfc::blake2b::Blake2b;
use byteorder::{BigEndian, ByteOrder};
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use rand::rngs::mock::StepRng;
use thiserror::Error;

/// A generalized Schnorr signature with a pedersen commitment value & blinding factors as the keys
#[derive(Clone, Debug)]
pub struct ComSignature {
	pub_nonce: Commitment,
	s: SecretKey,
	t: SecretKey,
}

/// Error types for Commitment Signatures
#[derive(Error, Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ComSigError {
	/// Invalid commitment signature
	#[error("Commitment signature is invalid")]
	InvalidSig,
	/// Secp256k1zkp error
	#[error("Secp256k1zkp error: {0:?}")]
	Secp256k1zkp(secp256k1zkp::Error),
}

impl From<secp256k1zkp::Error> for ComSigError {
	fn from(err: secp256k1zkp::Error) -> ComSigError {
		ComSigError::Secp256k1zkp(err)
	}
}

impl ComSignature {
	/// Create a new ComSignature
	pub fn new(pub_nonce: &Commitment, s: &SecretKey, t: &SecretKey) -> ComSignature {
		ComSignature {
			pub_nonce: pub_nonce.to_owned(),
			s: s.to_owned(),
			t: t.to_owned(),
		}
	}

	/// Sign commitment with amount, blinding factor, and message
	pub fn sign(
		amount: u64,
		blind: &SecretKey,
		msg: &Vec<u8>,
		use_test_rng: bool,
	) -> Result<ComSignature, ComSigError> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		let mut amt_bytes = [0; 32];
		BigEndian::write_u64(&mut amt_bytes[24..32], amount);
		let k_amt = SecretKey::from_slice(&secp, &amt_bytes)?;
		let k_1;
		let k_2;

		if use_test_rng {
			// allow for consistent test results
			let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
			k_1 = SecretKey::new(&secp, &mut test_rng);
			k_2 = SecretKey::new(&secp, &mut test_rng);
		} else {
			k_1 = SecretKey::new(&secp, &mut thread_rng());
			k_2 = SecretKey::new(&secp, &mut thread_rng());
		}

		let commitment = secp.commit(amount, blind.clone())?;
		let nonce_commitment = secp.commit_blind(k_1.clone(), k_2.clone())?;

		let e = ComSignature::calc_challenge(
			&secp,
			&commitment,
			&nonce_commitment,
			&msg,
			use_test_rng,
		)?;

		// s = k_1 + (e * amount)
		let mut s = k_amt.clone();
		s.mul_assign(&secp, &e)?;
		s.add_assign(&secp, &k_1)?;

		// t = k_2 + (e * blind)
		let mut t = blind.clone();
		t.mul_assign(&secp, &e)?;
		t.add_assign(&secp, &k_2)?;

		Ok(ComSignature::new(&nonce_commitment, &s, &t))
	}

	/// Verify the commitment signature
	pub fn verify(&self, commit: &Commitment, msg: &Vec<u8>) -> Result<(), ComSigError> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		let s1 = secp.commit_blind(self.s.clone(), self.t.clone())?;

		let mut ce = commit.to_pubkey(&secp)?;
		let e = ComSignature::calc_challenge(&secp, &commit, &self.pub_nonce, &msg, false)?;
		ce.mul_assign(&secp, &e)?;

		let commits = vec![Commitment::from_pubkey(&secp, &ce)?, self.pub_nonce.clone()];
		let s2 = secp.commit_sum(commits, Vec::new())?;

		if s1 != s2 {
			return Err(ComSigError::InvalidSig);
		}

		Ok(())
	}

	fn calc_challenge(
		secp: &Secp256k1,
		commit: &Commitment,
		nonce_commit: &Commitment,
		msg: &Vec<u8>,
		use_test_rng: bool,
	) -> Result<SecretKey, ComSigError> {
		let mut challenge_hasher = Blake2b::new(32);
		if use_test_rng {
			return Ok(super::secp::random_secret(use_test_rng));
		}
		challenge_hasher.update(&commit.0);
		challenge_hasher.update(&nonce_commit.0);
		challenge_hasher.update(msg);

		let mut challenge = [0; 32];
		challenge.copy_from_slice(challenge_hasher.finalize().as_bytes());

		Ok(SecretKey::from_slice(&secp, &challenge)?)
	}
}

/// Serializes a ComSignature to and from hex
pub mod comsig_serde {
	use super::ComSignature;
	use grin_core::ser::{self, ProtocolVersion};
	use grin_util::ToHex;
	use serde::{Deserialize, Serializer};

	/// Serializes a ComSignature as a hex string
	pub fn serialize<S>(comsig: &ComSignature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;
		let bytes = ser::ser_vec(&comsig, ProtocolVersion::local()).map_err(Error::custom)?;
		serializer.serialize_str(&bytes.to_hex())
	}

	/// Creates a ComSignature from a hex string
	pub fn deserialize<'de, D>(deserializer: D) -> Result<ComSignature, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		use serde::de::Error;
		let bytes = String::deserialize(deserializer)
			.and_then(|string| grin_util::from_hex(&string).map_err(Error::custom))?;
		let sig: ComSignature = ser::deserialize_default(&mut &bytes[..]).map_err(Error::custom)?;
		Ok(sig)
	}
}

#[allow(non_snake_case)]
impl Readable for ComSignature {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let R = Commitment::read(reader)?;
		let s = super::secp::read_secret_key(reader)?;
		let t = super::secp::read_secret_key(reader)?;
		Ok(ComSignature::new(&R, &s, &t))
	}
}

impl Writeable for ComSignature {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.pub_nonce.0)?;
		writer.write_fixed_bytes(self.s.0)?;
		writer.write_fixed_bytes(self.t.0)?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::{ComSigError, ComSignature, ContextFlag, Secp256k1, SecretKey};

	use grin_util::secp::rand::{thread_rng, RngCore};
	use rand::Rng;

	/// Test signing and verification of ComSignatures
	#[test]
	fn verify_comsig() -> Result<(), ComSigError> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		let amount = thread_rng().next_u64();
		let blind = SecretKey::new(&secp, &mut thread_rng());
		let msg: [u8; 16] = rand::thread_rng().gen();
		let comsig = ComSignature::sign(amount, &blind, &msg.to_vec(), false)?;

		let commit = secp.commit(amount, blind.clone())?;
		assert!(comsig.verify(&commit, &msg.to_vec()).is_ok());

		let wrong_msg: [u8; 16] = rand::thread_rng().gen();
		assert!(comsig.verify(&commit, &wrong_msg.to_vec()).is_err());

		let wrong_commit = secp.commit(amount, SecretKey::new(&secp, &mut thread_rng()))?;
		assert!(comsig.verify(&wrong_commit, &msg.to_vec()).is_err());

		Ok(())
	}
}
