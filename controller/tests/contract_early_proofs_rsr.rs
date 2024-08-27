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
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI};
use libwallet::{Slate, SlateState, Slatepack, Slatepacker, SlatepackerArgs, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};

/// Development + Tests of early payment proof functionality - RSR workflow
fn contract_early_proofs_rsr_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		sender_address = Some(api.get_slatepack_address(send_mask, 0)?.pub_key);
		Ok(())
	})?;

	let mut recipient_address = None;
	wallet::controller::owner_single_use(Some(recv_wallet.clone()), recv_mask, None, |api, m| {
		// Receive wallet (invoice) calls --receive=5
		let args = &mut ContractNewArgsAPI {
			setup_args: ContractSetupArgsAPI {
				net_change: Some(5_000_000_000),
				..Default::default()
			},
			..Default::default()
		};
		args.setup_args.proof_args.sender_address = sender_address;
		println!("SENDER ADDRESS: {:?}", sender_address);
		slate = api.contract_new(m, args)?;
		recipient_address = Some(api.get_slatepack_address(recv_mask, 0)?.pub_key);
		Ok(())
	})?;

	assert_eq!(slate.state, SlateState::Invoice1);
	println!("I1 State slate: {}", slate);

	// Serialize slate into slatepack
	let slatepacker_args = SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key: None,
	};

	let slate_packer = Slatepacker::new(slatepacker_args);
	let slate_packed = slate_packer.create_slatepack(&slate).unwrap();

	let slate_unpacked = slate_packer.get_slate(&slate_packed).unwrap();
	println!("I2 Slate unpacked: {}", slate_unpacked);

	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		// Sending wallet (invoice) signs
		let args = &ContractSetupArgsAPI {
			net_change: Some(-5_000_000_000),
			..Default::default()
		};
		slate = api.contract_sign(m, &slate_unpacked, args)?;
		Ok(())
	})?;
	println!("I2 State slate: {}", slate);

	assert_eq!(slate.state, SlateState::Invoice2);

	// Send wallet finalizes and posts
	wallet::controller::owner_single_use(Some(recv_wallet.clone()), recv_mask, None, |api, m| {
		let args = &ContractSetupArgsAPI {
			..Default::default()
		};
		slate = api.contract_sign(m, &slate, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Invoice3);

	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		api.post_tx(m, &slate, false)?;
		Ok(())
	})?;
	bh += 1;

	let _ =
		test_framework::award_blocks_to_wallet(&chain, send_wallet.clone(), send_mask, 3, false);
	bh += 3;

	// Assert changes in receive wallet
	wallet::controller::owner_single_use(Some(recv_wallet.clone()), recv_mask, None, |api, m| {
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
	})?;

	// Assert changes in send wallet
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
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
	})?;

	let mut invoice_proof = None;
	// Now some time has passed, sender retrieves and verify the payment proof
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, _m| {
		// Extract the stored data as an invoice proof
		invoice_proof =
			Some(api.retrieve_payment_proof_invoice(send_mask, true, None, Some(slate.id))?);
		Ok(())
	})?;

	let invoice_proof = invoice_proof.unwrap();
	let invoice_proof_json = serde_json::to_string(&invoice_proof).unwrap();

	// Should have all proof fields filled out
	println!("INVOICE PROOF: {}", invoice_proof_json);

	wallet::controller::foreign_single_use(recv_wallet.clone(), recv_mask.cloned(), |api| {
		let mut proof = serde_json::from_str(&invoice_proof_json).unwrap();
		api.verify_payment_proof_invoice(recipient_address.as_ref().unwrap(), &proof)?;
		// tweak something and it shouldn't verify
		proof.amount = 400000;
		let retval = api.verify_payment_proof_invoice(recipient_address.as_ref().unwrap(), &proof);
		assert!(retval.is_err());
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn contract_early_proofs_rsr() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_early_proofs_rsr";
	setup(test_dir);
	contract_early_proofs_rsr_test_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
