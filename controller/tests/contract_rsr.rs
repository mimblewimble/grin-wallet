// Copyright 2022 The Grin Developers
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

//! Test a wallet doing contract RSR flow
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use impls::test_framework::{self};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI};
use libwallet::{NodeVersionInfo, Slate, SlateState, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};
use std::path::PathBuf;

fn reject_contract_new(
	method: grin_wallet_api::ForeignCheckMiddlewareFn,
	_node_version: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	assert!(matches!(
		method,
		grin_wallet_api::ForeignCheckMiddlewareFn::ContractNew
	));
	assert!(slate.is_none());
	Err(libwallet::Error::GenericError(
		"Contract rejected by middleware".to_string(),
	))
}

/// contract RSR flow
fn contract_rsr_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create two wallets and mine 4 blocks in each (we want both to have balance to get a payjoin)
	let (wallets, chain, stopper, mut bh) =
		create_wallets(vec![vec![("default", 4)], vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();
	let recv_wallet = wallets[1].0.clone();
	let recv_mask = wallets[1].1.as_ref();
	let participant_fee = my_fee_contribution(1, 1, 1, 2)?.fee();

	// Receive wallet initiates an invoice transaction through the foreign API.
	let args = &ContractNewArgsAPI {
		ttl_blocks: None,
		setup_args: ContractSetupArgsAPI {
			selection_args: common::contract_selection_args(),
			net_change: Some(5_000_000_000),
			..Default::default()
		},
	};
	{
		let api = grin_wallet_api::Foreign::new(
			recv_wallet.clone(),
			PathBuf::from(test_dir),
			recv_mask.cloned(),
			Some(reject_contract_new),
			false,
		);
		let err = api.contract_new(args).unwrap_err();
		assert!(matches!(
			err,
			libwallet::Error::GenericError(ref msg)
				if msg == "Contract rejected by middleware"
		));
	}
	let mut slate = None;
	wallet::controller::foreign_single_use(
		recv_wallet.clone(),
		PathBuf::from(test_dir),
		recv_mask.cloned(),
		|api| {
			let rejected = ContractNewArgsAPI {
				ttl_blocks: args.ttl_blocks,
				setup_args: ContractSetupArgsAPI {
					net_change: Some(-5_000_000_000),
					..args.setup_args.clone()
				},
			};
			let err = api.contract_new(&rejected).unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Can't create a non-receiving contract from a foreign API."
			));
			slate = Some(api.contract_new(args)?);
			Ok(())
		},
	)?;
	let mut slate = slate.expect("foreign API returned no slate");
	assert_eq!(slate.state, SlateState::Invoice1);
	common::assert_basic_contract_slate(
		&slate,
		common::ExpectedContractSlate {
			amount: 5_000_000_000,
			fee: participant_fee,
			inputs: 0,
			coinbase_inputs: 0,
			outputs: 0,
			kernels: 0,
			num_participants: 2,
			participant_data: 1,
			signatures: 0,
		},
	);

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let wrong_args = ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				net_change: Some(5_000_000_000),
				..Default::default()
			};
			let err = api.contract_sign(m, &slate, &wrong_args).unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Expected net change -5000000000, got 5000000000 (did you mean --send instead of --receive?)"
			));

			// Send Wallet calls --send=5
			let args = &ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				net_change: Some(-5_000_000_000),
				..Default::default()
			};
			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Invoice2);
	common::assert_basic_contract_slate(
		&slate,
		common::ExpectedContractSlate {
			amount: 5_000_000_000,
			fee: 2 * participant_fee,
			inputs: 1,
			coinbase_inputs: 1,
			outputs: 1,
			kernels: 1,
			num_participants: 2,
			participant_data: 2,
			signatures: 1,
		},
	);

	// Receive wallet finalizes and posts
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let args = &mut ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				..Default::default()
			};
			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Invoice3);
	common::assert_basic_contract_slate(
		&slate,
		common::ExpectedContractSlate {
			amount: 5_000_000_000,
			fee: 2 * participant_fee,
			inputs: 2,
			coinbase_inputs: 2,
			outputs: 2,
			kernels: 1,
			num_participants: 2,
			participant_data: 2,
			signatures: 2,
		},
	);

	// Send wallet posts so receive wallet doesn't get the mined amount
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
			let expected_fees_paid = Some(my_fee_contribution(1, 1, 1, 2)?);
			assert_eq!(tx_log.fee, expected_fees_paid);
			assert_eq!(
				wallet_info.amount_currently_spendable,
				4 * 60_000_000_000 + 5_000_000_000 - expected_fees_paid.unwrap().fee() // we expect the balance of 4 mined blocks + 5 Grin - fees paid
			);
			// println!("txlogentry: {:#?}", tx_log);
			// println!("wallet info: {:#?}", wallet_info);
			// let (validated, commits) = api.retrieve_outputs(m, true, false, Some(tx_log.id))?;
			// println!("commits: {:#?}", commits);
			// panic!("lala");
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
			assert_eq!(txs.len() as u64, bh - 4 + 1); // send_wallet didn't mine 4 blocks and made 1 tx
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

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_contract_rsr_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_rsr_tx";
	setup(test_dir);
	contract_rsr_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
