// Copyright 2023 The Grin Developers
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

//! Development and testing of early payment proofs, restricted at the moment
//! to contract-style transactions for experimental purposes
//!
//! https://github.com/mimblewimble/grin-rfcs/pull/70
//!
//!

extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use grin_util::secp::{Secp256k1, Signature};
use impls::test_framework::{self};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{
	ContractNewArgsAPI, ContractSetupArgsAPI, PaymentMemo, ProofType,
};
use libwallet::{Slate, SlateState, Slatepacker, SlatepackerArgs, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};
use std::path::PathBuf;

fn roundtrip_slate(slate: &Slate, version: u16) -> Result<Slate, libwallet::Error> {
	let packer = Slatepacker::new(SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key: None,
	});
	let slate = packer.get_slate(&packer.create_slatepack(slate)?)?;
	assert_eq!(slate.version_info.version, version);
	Ok(slate)
}

/// Development + Tests of early payment proof functionality - RSR workflow
fn contract_early_proofs_rsr_test_impl(
	test_dir: &'static str,
	proof_type: ProofType,
) -> Result<(), libwallet::Error> {
	// create two wallets and mine 4 blocks in each (we want both to have balance to get a payjoin)
	let (wallets, chain, stopper, mut bh) =
		create_wallets(vec![vec![("default", 4)], vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();
	let recv_wallet = wallets[1].0.clone();
	let recv_mask = wallets[1].1.as_ref();

	let mut slate = Slate::blank(0, true); // this gets overriden below

	let mut sender_address = None;
	// Get sender address explicitly
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, _m| {
			sender_address = Some(api.get_slatepack_address(send_mask, 0)?.pub_key);
			Ok(())
		},
	)?;

	let mut recipient_address = None;
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Receive wallet (invoice) calls --receive=5
			let args = &mut ContractNewArgsAPI {
				setup_args: ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(5_000_000_000),
					..Default::default()
				},
				..Default::default()
			};
			// Proofs are opt-in; enable and supply the sender address.
			args.setup_args.proof_args.suppress_proof = false;
			args.setup_args.proof_args.proof_type = proof_type;
			args.setup_args.proof_args.memo = Some(PaymentMemo::new("RSR payment".into())?);
			args.setup_args.proof_args.sender_address = sender_address;
			slate = api.contract_new(m, args)?;
			recipient_address = Some(api.get_slatepack_address(recv_mask, 0)?.pub_key);
			Ok(())
		},
	)?;

	assert_eq!(slate.state, SlateState::Invoice1);
	println!("I1 State slate: {}", slate);
	slate = roundtrip_slate(&slate, 5)?;

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Sending wallet (invoice) signs
			let args = &ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				net_change: Some(-5_000_000_000),
				..Default::default()
			};
			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	println!("I2 State slate: {}", slate);

	assert_eq!(slate.state, SlateState::Invoice2);
	slate = roundtrip_slate(&slate, 5)?;

	// Send wallet finalizes and posts
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let args = &ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				..Default::default()
			};
			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Invoice3);
	slate = roundtrip_slate(&slate, 5)?;

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			api.post_tx(m, &slate, false)?;
			Ok(())
		},
	)?;
	bh += 1;

	let _ =
		test_framework::award_blocks_to_wallet(&chain, send_wallet.clone(), send_mask, 3, false);
	bh += 3;

	// Assert changes in receive wallet
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None, None)?;
			assert_eq!(wallet_info.last_confirmed_height, bh);
			assert!(refreshed);
			assert_eq!(txs.len(), 5); // 4 mined and 1 received
			let tx_log = txs[4].clone();
			assert_eq!(tx_log.tx_type, TxLogEntryType::TxReceived);
			assert_eq!(tx_log.amount_credited, 5_000_000_000);
			assert_eq!(tx_log.amount_debited, 0);
			assert_eq!(tx_log.num_inputs, 1);
			assert_eq!(tx_log.num_outputs, 1);
			let expected_fees_paid = Some(my_fee_contribution(1, 1, 1, 2)?);
			assert_eq!(tx_log.fee, expected_fees_paid);
			assert_eq!(
				wallet_info.amount_currently_spendable,
				4 * 60_000_000_000 + 5_000_000_000 - expected_fees_paid.unwrap().fee() // we expect the balance of 4 mined blocks + 5 Grin - fees paid
			);
			Ok(())
		},
	)?;

	// Assert changes in send wallet
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None, None)?;
			assert_eq!(wallet_info.last_confirmed_height, bh);
			assert!(refreshed);
			assert_eq!(txs.len() as u64, bh - 4 + 1); // send wallet didn't mine 4 blocks and made 1 tx
			let tx_log = txs[txs.len() - 5].clone(); // TODO: why -5 and not -4?
			assert_eq!(tx_log.tx_type, TxLogEntryType::TxSent);
			assert_eq!(tx_log.amount_credited, 0);
			assert_eq!(tx_log.amount_debited, 5_000_000_000);
			assert_eq!(tx_log.num_inputs, 1);
			assert_eq!(tx_log.num_outputs, 1);
			assert_eq!(tx_log.fee, Some(my_fee_contribution(1, 1, 1, 2)?));
			Ok(())
		},
	)?;

	let mut early_proof = None;
	// Now some time has passed, sender retrieves and verify the payment proof
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, _m| {
			// Extract the stored early payment proof
			early_proof =
				Some(api.retrieve_payment_proof_early(send_mask, true, None, Some(slate.id))?);
			Ok(())
		},
	)?;

	let early_proof = early_proof.unwrap();
	assert_eq!(early_proof.proof_type, proof_type);
	assert_eq!(early_proof.amount, 5_000_000_000);
	assert_eq!(
		early_proof.memo.as_ref().map(PaymentMemo::as_str),
		Some("RSR payment")
	);
	assert_eq!(
		early_proof
			.witness_data
			.as_ref()
			.unwrap()
			.sender_public_nonce
			.is_some(),
		proof_type == ProofType::SenderNonce
	);
	let early_proof_json = serde_json::to_string(&early_proof).unwrap();

	// Should have all proof fields filled out
	println!("EARLY PAYMENT PROOF: {}", early_proof_json);

	wallet::controller::foreign_single_use(
		recv_wallet.clone(),
		PathBuf::from(test_dir),
		recv_mask.cloned(),
		|api| {
			let mut proof = serde_json::from_str(&early_proof_json).unwrap();
			api.verify_payment_proof_early(recipient_address.as_ref().unwrap(), &proof)?;
			if proof_type == ProofType::SenderNonce {
				let mut invalid = proof.clone();
				let nonce = invalid
					.receiver_public_nonce
					.serialize_vec(&Secp256k1::new(), true);
				let sender_sig = &invalid.witness_data.as_ref().unwrap().sender_partial_sig;
				let mut raw_sig = [0; 64];
				raw_sig.copy_from_slice(&sender_sig[..]);
				raw_sig[..32].copy_from_slice(&nonce[1..]);
				invalid.witness_data.as_mut().unwrap().sender_partial_sig =
					Signature::from_raw_data(&raw_sig)?;
				let err =
					api.verify_payment_proof_early(recipient_address.as_ref().unwrap(), &invalid);
				assert!(matches!(
					err,
					Err(libwallet::Error::PaymentProofValidation(ref msg))
						if msg == "Sender partial signature nonce does not match the proof"
				));
			}
			// tweak something and it shouldn't verify
			proof.amount = 400000;
			let err = api.verify_payment_proof_early(recipient_address.as_ref().unwrap(), &proof);
			if proof_type == ProofType::SenderNonce {
				assert!(matches!(
					err,
					Err(libwallet::Error::PaymentProofValidation(ref msg))
						if msg == "Sender nonce does not commit to the payment details"
				));
			} else {
				assert!(err.is_err());
			}
			Ok(())
		},
	)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn contract_early_proofs_rsr() -> Result<(), libwallet::Error> {
	for (test_dir, proof_type) in [
		(
			"test_output/contract_early_proofs_rsr_invoice",
			ProofType::Invoice,
		),
		(
			"test_output/contract_early_proofs_rsr_sender_nonce",
			ProofType::SenderNonce,
		),
	] {
		setup(test_dir);
		contract_early_proofs_rsr_test_impl(test_dir, proof_type)?;
		clean_output_dir(test_dir);
	}
	Ok(())
}
