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

//! SECP operations for comsig

pub use grin_util::secp::{
	self as secp256k1zkp,
	constants::SECRET_KEY_SIZE,
	key::{SecretKey, ZERO_KEY},
	pedersen::Commitment,
	rand::thread_rng,
	ContextFlag, Secp256k1,
};

use grin_core::ser::{self, Reader};
use rand::rngs::mock::StepRng;

/// Generate a random SecretKey.
pub fn random_secret(use_test_rng: bool) -> SecretKey {
	let secp = Secp256k1::new();
	if use_test_rng {
		// allow for consistent test results
		let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
		SecretKey::new(&secp, &mut test_rng)
	} else {
		SecretKey::new(&secp, &mut thread_rng())
	}
}

/// Deserialize a SecretKey from a Reader
pub fn read_secret_key<R: Reader>(reader: &mut R) -> Result<SecretKey, ser::Error> {
	let buf = reader.read_fixed_bytes(SECRET_KEY_SIZE)?;
	let secp = Secp256k1::with_caps(ContextFlag::None);
	let pk = SecretKey::from_slice(&secp, &buf).map_err(|_| ser::Error::CorruptedData)?;
	Ok(pk)
}

/// Build a Pedersen Commitment using the provided value and blinding factor
#[cfg(test)]
pub fn commit(value: u64, blind: &SecretKey) -> Result<Commitment, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let commit = secp.commit(value, blind.clone())?;
	Ok(commit)
}

/// Add a blinding factor to an existing Commitment
pub fn add_excess(
	commitment: &Commitment,
	excess: &SecretKey,
) -> Result<Commitment, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let excess_commit: Commitment = secp.commit(0, excess.clone())?;

	let commits = vec![commitment.clone(), excess_commit.clone()];
	let sum = secp.commit_sum(commits, Vec::new())?;
	Ok(sum)
}

/// Subtracts a value (v*H) from an existing commitment
pub fn sub_value(commitment: &Commitment, value: u64) -> Result<Commitment, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let neg_commit: Commitment = secp.commit(value, ZERO_KEY)?;
	let sum = secp.commit_sum(vec![commitment.clone()], vec![neg_commit.clone()])?;
	Ok(sum)
}

/// Signs the message with the provided SecretKey
#[cfg(test)]
#[allow(dead_code)]
pub fn sign(
	sk: &SecretKey,
	msg: &grin_util::secp::Message,
) -> Result<grin_util::secp::Signature, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Full);
	let pubkey = grin_util::secp::PublicKey::from_secret_key(&secp, &sk)?;
	let sig = grin_util::secp::aggsig::sign_single(
		&secp,
		&msg,
		&sk,
		None,
		None,
		None,
		Some(&pubkey),
		None,
	)?;
	Ok(sig)
}
