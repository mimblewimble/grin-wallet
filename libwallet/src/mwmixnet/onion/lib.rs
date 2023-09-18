pub mod crypto;
pub mod onion;
pub mod util;

use crate::crypto::secp::{random_secret, Commitment, SecretKey};
use crate::onion::{new_stream_cipher, Onion, OnionError, Payload, RawBytes};

use chacha20::cipher::StreamCipher;
use grin_core::core::FeeFields;
use secp256k1zkp::pedersen::RangeProof;
use x25519_dalek::PublicKey as xPublicKey;
use x25519_dalek::{SharedSecret, StaticSecret};

#[derive(Clone)]
pub struct Hop {
	pub server_pubkey: xPublicKey,
	pub excess: SecretKey,
	pub fee: FeeFields,
	pub rangeproof: Option<RangeProof>,
}

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
pub fn create_onion(commitment: &Commitment, hops: &Vec<Hop>) -> Result<Onion, OnionError> {
	if hops.is_empty() {
		return Ok(Onion {
			ephemeral_pubkey: xPublicKey::from([0u8; 32]),
			commit: commitment.clone(),
			enc_payloads: vec![],
		});
	}

	let mut shared_secrets: Vec<SharedSecret> = Vec::new();
	let mut enc_payloads: Vec<RawBytes> = Vec::new();
	let mut ephemeral_sk = StaticSecret::from(random_secret().0);
	let onion_ephemeral_pk = xPublicKey::from(&ephemeral_sk);
	for i in 0..hops.len() {
		let hop = &hops[i];
		let shared_secret = ephemeral_sk.diffie_hellman(&hop.server_pubkey);
		shared_secrets.push(shared_secret);

		ephemeral_sk = StaticSecret::from(random_secret().0);
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

pub mod test_util {
	use super::*;
	use crate::crypto::dalek::DalekPublicKey;
	use crate::crypto::secp;

	use grin_core::core::hash::Hash;
	use grin_util::ToHex;
	use rand::{thread_rng, RngCore};
	use secp256k1zkp::Secp256k1;

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
				&random_secret(),
				&random_secret(),
				thread_rng().next_u32(),
				rangeproof,
			);
			hops.push(hop);
		}

		create_onion(&commit, &hops).unwrap()
	}

	pub fn rand_commit() -> Commitment {
		secp::commit(rand::thread_rng().next_u64(), &secp::random_secret()).unwrap()
	}

	pub fn rand_hash() -> Hash {
		Hash::from_hex(secp::random_secret().to_hex().as_str()).unwrap()
	}

	pub fn rand_proof() -> RangeProof {
		let secp = Secp256k1::new();
		secp.bullet_proof(
			rand::thread_rng().next_u64(),
			secp::random_secret(),
			secp::random_secret(),
			secp::random_secret(),
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
			secp::random_secret(),
			secp::random_secret(),
			None,
			None,
		);

		(secp::commit(out_value, &blind).unwrap(), rp)
	}

	pub fn rand_keypair() -> (SecretKey, DalekPublicKey) {
		let sk = random_secret();
		let pk = DalekPublicKey::from_secret(&sk);
		(sk, pk)
	}
}
