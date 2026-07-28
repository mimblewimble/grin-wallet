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

pub mod crypto;
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

/// Maximum number of servers in an mwixnet route.
pub const MAX_MWIXNET_HOPS: usize = 16;

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
#[cfg(any(test, feature = "mwixnet-test"))]
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
	if hops.len() > MAX_MWIXNET_HOPS {
		return Err(OnionError::TooManyHops {
			max: MAX_MWIXNET_HOPS,
		});
	}
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
		if !shared_secret.was_contributory() {
			return Err(OnionError::NonContributorySharedSecret);
		}
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
#[cfg(any(test, feature = "mwixnet-test"))]
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mwixnet::MwixnetServerPublicKey;

	#[test]
	fn rejects_zero_key() {
		let commitment = test_util::rand_commit();
		let hop = Hop {
			server_pubkey: xPublicKey::from([0u8; 32]),
			excess: random_secret(false),
			fee: FeeFields::from(1u32),
			rangeproof: None,
		};

		assert_eq!(
			create_onion(&commitment, &vec![hop], false),
			Err(OnionError::NonContributorySharedSecret)
		);
	}

	#[test]
	fn rejects_too_many_hops() {
		let commitment = test_util::rand_commit();
		let hops: Vec<Hop> = (0..=MAX_MWIXNET_HOPS)
			.map(|_| {
				let server_key = random_secret(false);
				Hop {
					server_pubkey: xPublicKey::from(&StaticSecret::from(server_key.0)),
					excess: random_secret(false),
					fee: FeeFields::from(1u32),
					rangeproof: None,
				}
			})
			.collect();
		let max_hops = hops[..MAX_MWIXNET_HOPS].to_vec();

		assert!(create_onion(&commitment, &max_hops, false).is_ok());

		assert_eq!(
			create_onion(&commitment, &hops, false),
			Err(OnionError::TooManyHops {
				max: MAX_MWIXNET_HOPS
			})
		);
	}

	#[test]
	fn x25519_key_roundtrip() {
		let server_key = SecretKey::from_slice(
			&grin_util::secp::Secp256k1::new(),
			&grin_util::from_hex(
				"a129111d283b13bf93957c06bf6605c3417b4b89db4b5cb2e7dab2c15e36e0a4",
			)
			.unwrap(),
		)
		.unwrap();
		let public_key = MwixnetServerPublicKey::from_secret(&server_key);
		assert_eq!(
			public_key.to_hex(),
			"96ced236bdf1aca722ef68b818445755e6ed4bacf23e19d7b71c43efc5f0077b"
		);
		let identity_key = crypto::dalek::DalekPublicKey::from_secret(&server_key).to_hex();
		assert_ne!(identity_key, public_key.to_hex());

		let commitment = crypto::secp::commit(1_000, &server_key).unwrap();
		let excess = server_key.clone();
		let hop = Hop {
			server_pubkey: xPublicKey::from(public_key.to_bytes()),
			excess: excess.clone(),
			fee: FeeFields::from(1u32),
			rangeproof: None,
		};
		let onion = create_onion(&commitment, &vec![hop], true).unwrap();
		let peeled = onion.peel_layer(&server_key).unwrap();

		assert_eq!(peeled.payload.excess, excess);
		assert_eq!(peeled.payload.fee, FeeFields::from(1u32));

		let identity_key = MwixnetServerPublicKey::from_hex(&identity_key).unwrap();
		let wrong_hop = Hop {
			server_pubkey: xPublicKey::from(identity_key.to_bytes()),
			excess: server_key.clone(),
			fee: FeeFields::from(1u32),
			rangeproof: None,
		};
		let wrong_onion = create_onion(&commitment, &vec![wrong_hop], true).unwrap();
		assert!(wrong_onion.peel_layer(&server_key).is_err());
	}
}
