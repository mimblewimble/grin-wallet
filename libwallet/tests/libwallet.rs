// Copyright 2018 The Grin Developers
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

//! core::libtx specific tests
use grin_wallet_libwallet::Context;
use grin_wallet_util::grin_core::core::transaction;
use grin_wallet_util::grin_core::libtx::{aggsig, proof};
use grin_wallet_util::grin_keychain::{
	BlindSum, BlindingFactor, ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType,
};
use grin_wallet_util::grin_util::secp;
use grin_wallet_util::grin_util::secp::key::{PublicKey, SecretKey};
use rand::thread_rng;

fn kernel_sig_msg() -> secp::Message {
	transaction::kernel_sig_msg(0, 0, transaction::KernelFeatures::Plain).unwrap()
}

#[test]
fn aggsig_sender_receiver_interaction() {
	let parent = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
	let switch = &SwitchCommitmentType::Regular;
	let sender_keychain = ExtKeychain::from_random_seed(true).unwrap();
	let receiver_keychain = ExtKeychain::from_random_seed(true).unwrap();

	// Calculate the kernel excess here for convenience.
	// Normally this would happen during transaction building.
	let kernel_excess = {
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let skey1 = sender_keychain.derive_key(0, &id1, switch).unwrap();
		let skey2 = receiver_keychain.derive_key(0, &id1, switch).unwrap();

		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let blinding_factor = keychain
			.blind_sum(
				&BlindSum::new()
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey1))
					.add_blinding_factor(BlindingFactor::from_secret_key(skey2)),
			)
			.unwrap();

		keychain
			.secp()
			.commit(0, blinding_factor.secret_key(&keychain.secp()).unwrap())
			.unwrap()
	};

	let s_cx;
	let mut rx_cx;
	// sender starts the tx interaction
	let (sender_pub_excess, _sender_pub_nonce) = {
		let keychain = sender_keychain.clone();
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let skey = keychain.derive_key(0, &id1, switch).unwrap();

		// dealing with an input here so we need to negate the blinding_factor
		// rather than use it as is
		let bs = BlindSum::new();
		let blinding_factor = keychain
			.blind_sum(&bs.sub_blinding_factor(BlindingFactor::from_secret_key(skey)))
			.unwrap();

		let blind = blinding_factor.secret_key(&keychain.secp()).unwrap();

		s_cx = Context::new(&keychain.secp(), blind, &parent, false, 0);
		s_cx.get_public_keys(&keychain.secp())
	};

	let pub_nonce_sum;
	let pub_key_sum;
	// receiver receives partial tx
	let (receiver_pub_excess, _receiver_pub_nonce, rx_sig_part) = {
		let keychain = receiver_keychain.clone();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		// let blind = blind_sum.secret_key(&keychain.secp())?;
		let blind = keychain.derive_key(0, &key_id, switch).unwrap();

		rx_cx = Context::new(&keychain.secp(), blind, &parent, false, 1);
		let (pub_excess, pub_nonce) = rx_cx.get_public_keys(&keychain.secp());
		rx_cx.add_output(&key_id, &None, 0);

		pub_nonce_sum = PublicKey::from_combination(
			keychain.secp(),
			vec![
				&s_cx.get_public_keys(keychain.secp()).1,
				&rx_cx.get_public_keys(keychain.secp()).1,
			],
		)
		.unwrap();

		pub_key_sum = PublicKey::from_combination(
			keychain.secp(),
			vec![
				&s_cx.get_public_keys(keychain.secp()).0,
				&rx_cx.get_public_keys(keychain.secp()).0,
			],
		)
		.unwrap();

		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&keychain.secp(),
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			Some(&pub_key_sum),
			&msg,
		)
		.unwrap();
		(pub_excess, pub_nonce, sig_part)
	};

	// check the sender can verify the partial signature
	// received in the response back from the receiver
	{
		let keychain = sender_keychain.clone();
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&keychain.secp(),
			&rx_sig_part,
			&pub_nonce_sum,
			&receiver_pub_excess,
			Some(&pub_key_sum),
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// now sender signs with their key
	let sender_sig_part = {
		let keychain = sender_keychain.clone();
		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&keychain.secp(),
			&s_cx.sec_key,
			&s_cx.sec_nonce,
			&pub_nonce_sum,
			Some(&pub_key_sum),
			&msg,
		)
		.unwrap();
		sig_part
	};

	// check the receiver can verify the partial signature
	// received by the sender
	{
		let keychain = receiver_keychain.clone();
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&keychain.secp(),
			&sender_sig_part,
			&pub_nonce_sum,
			&sender_pub_excess,
			Some(&pub_key_sum),
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// Receiver now builds final signature from sender and receiver parts
	let (final_sig, final_pubkey) = {
		let keychain = receiver_keychain.clone();

		let msg = kernel_sig_msg();
		let our_sig_part = aggsig::calculate_partial_sig(
			&keychain.secp(),
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			Some(&pub_key_sum),
			&msg,
		)
		.unwrap();

		// Receiver now generates final signature from the two parts
		let final_sig = aggsig::add_signatures(
			&keychain.secp(),
			vec![&sender_sig_part, &our_sig_part],
			&pub_nonce_sum,
		)
		.unwrap();

		// Receiver calculates the final public key (to verify sig later)
		let final_pubkey = PublicKey::from_combination(
			keychain.secp(),
			vec![
				&s_cx.get_public_keys(keychain.secp()).0,
				&rx_cx.get_public_keys(keychain.secp()).0,
			],
		)
		.unwrap();

		(final_sig, final_pubkey)
	};

	// Receiver checks the final signature verifies
	{
		let keychain = receiver_keychain.clone();
		let msg = kernel_sig_msg();

		// Receiver check the final signature verifies
		let sig_verifies = aggsig::verify_completed_sig(
			&keychain.secp(),
			&final_sig,
			&final_pubkey,
			Some(&final_pubkey),
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// Check we can verify the sig using the kernel excess
	{
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let msg = kernel_sig_msg();
		let sig_verifies =
			aggsig::verify_single_from_commit(&keychain.secp(), &final_sig, &msg, &kernel_excess);

		assert!(!sig_verifies.is_err());
	}
}

#[test]
fn aggsig_sender_receiver_interaction_offset() {
	let parent = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
	let switch = &SwitchCommitmentType::Regular;
	let sender_keychain = ExtKeychain::from_random_seed(true).unwrap();
	let receiver_keychain = ExtKeychain::from_random_seed(true).unwrap();

	// This is the kernel offset that we use to split the key
	// Summing these at the block level prevents the
	// kernels from being used to reconstruct (or identify) individual transactions
	let kernel_offset = SecretKey::new(&sender_keychain.secp(), &mut thread_rng());

	// Calculate the kernel excess here for convenience.
	// Normally this would happen during transaction building.
	let kernel_excess = {
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let skey1 = sender_keychain.derive_key(0, &id1, switch).unwrap();
		let skey2 = receiver_keychain.derive_key(0, &id1, switch).unwrap();

		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let blinding_factor = keychain
			.blind_sum(
				&BlindSum::new()
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey1))
					.add_blinding_factor(BlindingFactor::from_secret_key(skey2))
					// subtract the kernel offset here like as would when
					// verifying a kernel signature
					.sub_blinding_factor(BlindingFactor::from_secret_key(kernel_offset.clone())),
			)
			.unwrap();

		keychain
			.secp()
			.commit(0, blinding_factor.secret_key(&keychain.secp()).unwrap())
			.unwrap()
	};

	let s_cx;
	let mut rx_cx;
	// sender starts the tx interaction
	let (sender_pub_excess, _sender_pub_nonce) = {
		let keychain = sender_keychain.clone();
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let skey = keychain.derive_key(0, &id1, switch).unwrap();

		// dealing with an input here so we need to negate the blinding_factor
		// rather than use it as is
		let blinding_factor = keychain
			.blind_sum(
				&BlindSum::new()
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey))
					// subtract the kernel offset to create an aggsig context
					// with our "split" key
					.sub_blinding_factor(BlindingFactor::from_secret_key(kernel_offset)),
			)
			.unwrap();

		let blind = blinding_factor.secret_key(&keychain.secp()).unwrap();

		s_cx = Context::new(&keychain.secp(), blind, &parent, false, 0);
		s_cx.get_public_keys(&keychain.secp())
	};

	// receiver receives partial tx
	let pub_nonce_sum;
	let pub_key_sum;
	let (receiver_pub_excess, _receiver_pub_nonce, sig_part) = {
		let keychain = receiver_keychain.clone();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let blind = keychain.derive_key(0, &key_id, switch).unwrap();

		rx_cx = Context::new(&keychain.secp(), blind, &parent, false, 1);
		let (pub_excess, pub_nonce) = rx_cx.get_public_keys(&keychain.secp());
		rx_cx.add_output(&key_id, &None, 0);

		pub_nonce_sum = PublicKey::from_combination(
			keychain.secp(),
			vec![
				&s_cx.get_public_keys(keychain.secp()).1,
				&rx_cx.get_public_keys(keychain.secp()).1,
			],
		)
		.unwrap();

		pub_key_sum = PublicKey::from_combination(
			keychain.secp(),
			vec![
				&s_cx.get_public_keys(keychain.secp()).0,
				&rx_cx.get_public_keys(keychain.secp()).0,
			],
		)
		.unwrap();

		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&keychain.secp(),
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			Some(&pub_key_sum),
			&msg,
		)
		.unwrap();
		(pub_excess, pub_nonce, sig_part)
	};

	// check the sender can verify the partial signature
	// received in the response back from the receiver
	{
		let keychain = sender_keychain.clone();
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&keychain.secp(),
			&sig_part,
			&pub_nonce_sum,
			&receiver_pub_excess,
			Some(&pub_key_sum),
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// now sender signs with their key
	let sender_sig_part = {
		let keychain = sender_keychain.clone();
		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&keychain.secp(),
			&s_cx.sec_key,
			&s_cx.sec_nonce,
			&pub_nonce_sum,
			Some(&pub_key_sum),
			&msg,
		)
		.unwrap();
		sig_part
	};

	// check the receiver can verify the partial signature
	// received by the sender
	{
		let keychain = receiver_keychain.clone();
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&keychain.secp(),
			&sender_sig_part,
			&pub_nonce_sum,
			&sender_pub_excess,
			Some(&pub_key_sum),
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// Receiver now builds final signature from sender and receiver parts
	let (final_sig, final_pubkey) = {
		let keychain = receiver_keychain.clone();
		let msg = kernel_sig_msg();
		let our_sig_part = aggsig::calculate_partial_sig(
			&keychain.secp(),
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			Some(&pub_key_sum),
			&msg,
		)
		.unwrap();

		// Receiver now generates final signature from the two parts
		let final_sig = aggsig::add_signatures(
			&keychain.secp(),
			vec![&sender_sig_part, &our_sig_part],
			&pub_nonce_sum,
		)
		.unwrap();

		// Receiver calculates the final public key (to verify sig later)
		let final_pubkey = PublicKey::from_combination(
			keychain.secp(),
			vec![
				&s_cx.get_public_keys(keychain.secp()).0,
				&rx_cx.get_public_keys(keychain.secp()).0,
			],
		)
		.unwrap();

		(final_sig, final_pubkey)
	};

	// Receiver checks the final signature verifies
	{
		let keychain = receiver_keychain.clone();
		let msg = kernel_sig_msg();

		// Receiver check the final signature verifies
		let sig_verifies = aggsig::verify_completed_sig(
			&keychain.secp(),
			&final_sig,
			&final_pubkey,
			Some(&final_pubkey),
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// Check we can verify the sig using the kernel excess
	{
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let msg = kernel_sig_msg();
		let sig_verifies =
			aggsig::verify_single_from_commit(&keychain.secp(), &final_sig, &msg, &kernel_excess);

		assert!(!sig_verifies.is_err());
	}
}

#[test]
fn test_rewind_range_proof() {
	let keychain = ExtKeychain::from_random_seed(true).unwrap();
	let builder = proof::ProofBuilder::new(&keychain);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let switch = &SwitchCommitmentType::Regular;
	let commit = keychain.commit(5, &key_id, switch).unwrap();
	let extra_data = [99u8; 64];

	let proof = proof::create(
		&keychain,
		&builder,
		5,
		&key_id,
		switch,
		commit,
		Some(extra_data.to_vec().clone()),
	)
	.unwrap();
	let proof_info = proof::rewind(
		keychain.secp(),
		&builder,
		commit,
		Some(extra_data.to_vec().clone()),
		proof,
	)
	.unwrap();

	assert!(proof_info.is_some());
	let (r_amount, r_key_id, r_switch) = proof_info.unwrap();
	assert_eq!(r_amount, 5);
	assert_eq!(r_key_id, key_id);
	assert_eq!(&r_switch, switch);

	// cannot rewind with a different commit
	let commit2 = keychain.commit(5, &key_id2, switch).unwrap();
	let proof_info = proof::rewind(
		keychain.secp(),
		&builder,
		commit2,
		Some(extra_data.to_vec().clone()),
		proof,
	)
	.unwrap();
	assert!(proof_info.is_none());

	// cannot rewind with a commitment to a different value
	let commit3 = keychain.commit(4, &key_id, switch).unwrap();
	let proof_info = proof::rewind(
		keychain.secp(),
		&builder,
		commit3,
		Some(extra_data.to_vec().clone()),
		proof,
	)
	.unwrap();
	assert!(proof_info.is_none());

	// cannot rewind with wrong extra committed data
	let wrong_extra_data = [98u8; 64];
	let proof_info = proof::rewind(
		keychain.secp(),
		&builder,
		commit,
		Some(wrong_extra_data.to_vec().clone()),
		proof,
	)
	.unwrap();
	assert!(proof_info.is_none());
}
