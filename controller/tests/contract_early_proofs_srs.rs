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

use impls::test_framework::{self};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::PaymentMemo;
use libwallet::{NodeVersionInfo, Slate, SlateState, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};
use std::path::PathBuf;

fn reject_proof_verification(
	method: grin_wallet_api::ForeignCheckMiddlewareFn,
	_node_version: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	assert!(matches!(
		method,
		grin_wallet_api::ForeignCheckMiddlewareFn::VerifyPaymentProofEarly
	));
	assert!(slate.is_none());
	Err(libwallet::Error::GenericError(
		"Proof rejected by middleware".to_string(),
	))
}

/// Development + Tests of early payment proof functionality
fn contract_early_proofs_srs_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create two wallets and mine 4 blocks in each (we want both to have balance to get a payjoin)
	let (wallets, chain, stopper, mut bh) =
		create_wallets(vec![vec![("default", 4)], vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();
	let recv_wallet = wallets[1].0.clone();
	let recv_mask = wallets[1].1.as_ref();

	let mut slate = Slate::blank(0, true); // this gets overriden below

	let mut sender_address = None;
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Send wallet inititates a standard transaction with --send=5
			let args = &common::contract_new_args(-5_000_000_000);
			slate = api.contract_new(m, args)?;
			sender_address = Some(api.get_slatepack_address(send_mask, 0)?.pub_key);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard1);
	slate = common::roundtrip_slate(&slate, 4)?;

	let mut recipient_address = None;
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Receive wallet calls --receive=5
			let args = &mut common::contract_setup_args(Some(5_000_000_000));
			// Proofs are opt-in; enable and supply the sender address.
			args.proof_args.suppress_proof = false;
			args.proof_args.memo = Some(PaymentMemo::new("SRS payment".into())?);
			args.proof_args.sender_address = sender_address;
			slate = api.contract_sign(m, &slate, args)?;
			recipient_address = Some(api.get_slatepack_address(recv_mask, 0)?.pub_key);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard2);
	slate = common::roundtrip_slate(&slate, 5)?;

	// Send wallet finalizes and posts
	//let mut sender_part_sig = None;
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let args = &common::contract_setup_args(None);
			let mut tampered = slate.clone();
			let proof = tampered.payment_proof.as_mut().unwrap();
			*proof.timestamp.as_mut().unwrap() += Duration::from_secs(1);
			assert!(api.contract_sign(m, &tampered, args).is_err());

			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard3);
	slate = common::roundtrip_slate(&slate, 5)?;

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
			let tx_log = common::tx_log_for_slate(api, m, &slate)?;
			assert_eq!(tx_log.tx_type, TxLogEntryType::TxReceived);
			assert_eq!(tx_log.amount_credited, 5_000_000_000);
			assert_eq!(tx_log.amount_debited, 0);
			assert_eq!(tx_log.num_inputs, 1);
			assert_eq!(tx_log.num_outputs, 1);
			let expected_fees_paid = my_fee_contribution(1, 1, 1, 2)?;
			assert_eq!(tx_log.fee, Some(expected_fees_paid));
			assert_eq!(
				wallet_info.amount_currently_spendable,
				4 * 60_000_000_000 + 5_000_000_000 - expected_fees_paid.fee() // we expect the balance of 4 mined blocks + 5 Grin - fees paid
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
			let tx_log = common::tx_log_for_slate(api, m, &slate)?;
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
	assert_eq!(early_proof.amount, 5_000_000_000);
	assert_eq!(
		early_proof.memo.as_ref().map(PaymentMemo::as_str),
		Some("SRS payment")
	);
	let early_proof_json = serde_json::to_string(&early_proof).unwrap();

	{
		let api = grin_wallet_api::Foreign::new(
			recv_wallet.clone(),
			PathBuf::from(test_dir),
			recv_mask.cloned(),
			Some(reject_proof_verification),
			false,
		);
		let err = api
			.verify_payment_proof_early(recipient_address.as_ref().unwrap(), &early_proof)
			.unwrap_err();
		assert!(matches!(
			err,
			libwallet::Error::GenericError(ref msg)
				if msg == "Proof rejected by middleware"
		));
	}

	wallet::controller::foreign_single_use(
		recv_wallet.clone(),
		PathBuf::from(test_dir),
		recv_mask.cloned(),
		|api| {
			let mut proof = serde_json::from_str(&early_proof_json).unwrap();
			api.verify_payment_proof_early(recipient_address.as_ref().unwrap(), &proof)?;
			// tweak something and it shouldn't verify
			proof.amount = 400000;
			let retval =
				api.verify_payment_proof_early(recipient_address.as_ref().unwrap(), &proof);
			assert!(retval.is_err());
			Ok(())
		},
	)?;

	// export and verify through the CLI
	let proof_file = format!("{}/early_proof.json", test_dir);
	let tampered_file = format!("{}/early_proof_tampered.json", test_dir);
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			wallet::command::proof_export(
				api,
				m,
				wallet::command::ProofExportArgs {
					output_file: proof_file.clone(),
					id: None,
					tx_slate_id: Some(slate.id),
				},
			)
			.map_err(|e| libwallet::Error::GenericError(e.to_string()))?;
			wallet::command::proof_verify(
				api,
				m,
				wallet::command::ProofVerifyArgs {
					input_file: proof_file.clone(),
				},
			)
			.map_err(|e| libwallet::Error::GenericError(e.to_string()))?;
			// tweak the amount and it shouldn't verify
			let mut tampered: serde_json::Value =
				serde_json::from_str(&std::fs::read_to_string(&proof_file).unwrap()).unwrap();
			tampered["proof"]["amount"] = serde_json::Value::from("400000");
			std::fs::write(&tampered_file, tampered.to_string()).unwrap();
			let retval = wallet::command::proof_verify(
				api,
				m,
				wallet::command::ProofVerifyArgs {
					input_file: tampered_file.clone(),
				},
			);
			assert!(retval.is_err());
			Ok(())
		},
	)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn contract_early_proofs_srs() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_early_proofs_src";
	setup(test_dir);
	contract_early_proofs_srs_test_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
