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

//! Onion module definition

mod crypto;
pub mod onion;
pub mod util;

pub use crypto::{
	comsig_serde, dalek::DalekPublicKey as MwixnetPublicKey, ComSigError, ComSignature,
};

use chacha20::cipher::StreamCipher;
use grin_core::core::FeeFields;
use grin_util::secp::{
	pedersen::{Commitment, RangeProof},
	SecretKey,
};
use x25519_dalek::PublicKey as xPublicKey;
use x25519_dalek::{SharedSecret, StaticSecret};

use crypto::secp::random_secret;
use onion::{new_stream_cipher, Onion, OnionError, Payload, RawBytes};

/// Onion hop struct
#[derive(Clone)]
pub struct Hop {
	/// Comsig server public key
	pub server_pubkey: xPublicKey,
	/// Kernel excess
	pub excess: SecretKey,
	/// Fee
	pub fee: FeeFields,
	/// Rangeproof
	pub rangeproof: Option<RangeProof>,
}

/// Crate a new hop
#[cfg(test)]
pub fn new_hop(
	server_key: &SecretKey,
	hop_excess: &SecretKey,
	fee: u32,
	proof: Option<RangeProof>,
) -> Hop {
	Hop {
		server_pubkey: xPublicKey::from(&StaticSecret::from(server_key.0.clone())),
		excess: hop_excess.clone(),
		fee: FeeFields::from(fee as u32),
		rangeproof: proof,
	}
}

/// Create an Onion for the Commitment, encrypting the payload for each hop
pub fn create_onion(
	commitment: &Commitment,
	hops: &Vec<Hop>,
	use_test_rng: bool,
) -> Result<Onion, OnionError> {
	if hops.is_empty() {
		return Ok(Onion {
			ephemeral_pubkey: xPublicKey::from([0u8; 32]),
			commit: commitment.clone(),
			enc_payloads: vec![],
		});
	}

	let mut shared_secrets: Vec<SharedSecret> = Vec::new();
	let mut enc_payloads: Vec<RawBytes> = Vec::new();
	let mut ephemeral_sk = StaticSecret::from(random_secret(use_test_rng).0);
	let onion_ephemeral_pk = xPublicKey::from(&ephemeral_sk);
	for i in 0..hops.len() {
		let hop = &hops[i];
		let shared_secret = ephemeral_sk.diffie_hellman(&hop.server_pubkey);
		shared_secrets.push(shared_secret);

		ephemeral_sk = StaticSecret::from(random_secret(use_test_rng).0);
		let next_ephemeral_pk = if i < (hops.len() - 1) {
			xPublicKey::from(&ephemeral_sk)
		} else {
			xPublicKey::from([0u8; 32])
		};

		let payload = Payload {
			next_ephemeral_pk,
			excess: hop.excess.clone(),
			fee: hop.fee.clone(),
			rangeproof: hop.rangeproof.clone(),
		};
		enc_payloads.push(payload.serialize()?);
	}

	for i in (0..shared_secrets.len()).rev() {
		let mut cipher = new_stream_cipher(&shared_secrets[i])?;
		for j in i..shared_secrets.len() {
			cipher.apply_keystream(&mut enc_payloads[j]);
		}
	}

	let onion = Onion {
		ephemeral_pubkey: onion_ephemeral_pk,
		commit: commitment.clone(),
		enc_payloads,
	};
	Ok(onion)
}

/// Internal tests
#[allow(missing_docs, dead_code)]
#[cfg(test)]
pub mod test_util {
	use super::*;
	use crypto::dalek::DalekPublicKey;
	use crypto::secp;

	use grin_core::core::hash::Hash;
	use grin_util::secp::Secp256k1;
	use grin_util::ToHex;
	use rand::{thread_rng, RngCore};

	pub fn rand_onion() -> Onion {
		let commit = rand_commit();
		let mut hops = Vec::new();
		let k = (thread_rng().next_u64() % 5) + 1;
		for i in 0..k {
			let rangeproof = if i == (k - 1) {
				Some(rand_proof())
			} else {
				None
			};
			let hop = new_hop(
				&random_secret(false),
				&random_secret(false),
				thread_rng().next_u32(),
				rangeproof,
			);
			hops.push(hop);
		}

		create_onion(&commit, &hops, false).unwrap()
	}

	pub fn rand_commit() -> Commitment {
		secp::commit(rand::thread_rng().next_u64(), &secp::random_secret(false)).unwrap()
	}

	pub fn rand_hash() -> Hash {
		Hash::from_hex(secp::random_secret(false).to_hex().as_str()).unwrap()
	}

	pub fn rand_proof() -> RangeProof {
		let secp = Secp256k1::new();
		secp.bullet_proof(
			rand::thread_rng().next_u64(),
			secp::random_secret(false),
			secp::random_secret(false),
			secp::random_secret(false),
			None,
			None,
		)
	}

	pub fn proof(
		value: u64,
		fee: u32,
		input_blind: &SecretKey,
		hop_excesses: &Vec<&SecretKey>,
	) -> (Commitment, RangeProof) {
		let secp = Secp256k1::new();

		let mut blind = input_blind.clone();
		for hop_excess in hop_excesses {
			blind.add_assign(&secp, &hop_excess).unwrap();
		}

		let out_value = value - (fee as u64);

		let rp = secp.bullet_proof(
			out_value,
			blind.clone(),
			secp::random_secret(false),
			secp::random_secret(false),
			None,
			None,
		);

		(secp::commit(out_value, &blind).unwrap(), rp)
	}

	pub fn rand_keypair() -> (SecretKey, DalekPublicKey) {
		let sk = random_secret(false);
		let pk = DalekPublicKey::from_secret(&sk);
		(sk, pk)
	}
}
