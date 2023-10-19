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

//! Test a wallet doing contract self-spend flow by using custom inputs and creating custom outputs
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use grin_core::consensus;
use impls::test_framework::{self};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI, OutputSelectionArgs};
use libwallet::{OutputStatus, Slate, SlateState, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};

/// contract self-spend flow with custom picked inputs and outputs
fn contract_self_spend_custom_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create a single wallet and mine 4 blocks
	let (wallets, chain, stopper, mut bh) =
		create_wallets(vec![vec![("default", 10)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();

	let mut use_inputs = String::from("");

	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		let (_, commits) = api.retrieve_outputs(m, true, false, None)?;
		println!("OOOT: {:?}", commits[0].output);
		use_inputs = format!(
			"{},{}",
			commits[0].output.commit.as_ref().unwrap(),
			commits[1].output.commit.as_ref().unwrap()
		);
		Ok(())
	})?;

	let mut slate = Slate::blank(0, true); // this gets overriden below

	let selection_args = OutputSelectionArgs {
		min_input_confirmation: 0,
		use_inputs: Some(use_inputs.clone()), // we will use two coinbase inputs
		make_outputs: Some(String::from("88,35,3,0.2,15")), // the sum is such that it will need to pick another input making total of 3 inputs
	};
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		// Send wallet inititates a standard transaction with --send=0
		let args = &ContractNewArgsAPI {
			setup_args: ContractSetupArgsAPI {
				net_change: Some(0),
				num_participants: 1,
				selection_args: selection_args.clone(),
				..Default::default()
			},
			..Default::default()
		};
		slate = api.contract_new(m, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard1);

	// Send wallet finalizes and posts
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		let args = &ContractSetupArgsAPI {
			..Default::default()
		};
		slate = api.contract_sign(m, &slate, args)?;
		Ok(())
	})?;
	// In the case of a self-spend, we just finish the slate when it's in the Standard2 state
	assert_eq!(slate.state, SlateState::Standard2);

	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		api.post_tx(m, &slate, false)?;
		Ok(())
	})?;
	bh += 1;

	let _ =
		test_framework::award_blocks_to_wallet(&chain, send_wallet.clone(), send_mask, 3, false);
	bh += 3;

	// Assert changes in send wallet
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		let (_, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(wallet_info.last_confirmed_height, bh);
		assert!(refreshed);
		assert_eq!(txs.len() as u64, bh + 1); // send wallet didn't mine 4 blocks and made 1 tx
		let tx_log = txs[txs.len() - 5].clone(); // TODO: why -5 and not -4?
		assert_eq!(tx_log.tx_type, TxLogEntryType::TxSelfSpend);
		assert_eq!(tx_log.amount_credited, 0);
		assert_eq!(tx_log.amount_debited, 0);
		assert_eq!(tx_log.num_inputs, 3);
		assert_eq!(tx_log.num_outputs, 6);
		assert_eq!(tx_log.fee, Some(my_fee_contribution(3, 6, 1, 1)?));
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		let (_, commits) = api.retrieve_outputs(m, true, false, None)?;
		// Assert used inputs are the ones we specified
		let used_inputs = use_inputs.split(",").collect::<Vec<&str>>();
		assert_eq!(commits[0].output.status, OutputStatus::Spent);
		assert_eq!(commits[0].output.commit.as_ref().unwrap(), used_inputs[0]);
		assert_eq!(commits[1].output.status, OutputStatus::Spent);
		assert_eq!(commits[1].output.commit.as_ref().unwrap(), used_inputs[1]);
		assert_eq!(commits[2].output.status, OutputStatus::Spent);
		// Assert expected outputs were created
		// 88, 35, 3, 0.2, 15 and a change output
		assert_eq!(commits[10].output.value, 88 * consensus::GRIN_BASE);
		assert_eq!(commits[11].output.value, 35 * consensus::GRIN_BASE);
		assert_eq!(commits[12].output.value, 3 * consensus::GRIN_BASE);
		assert_eq!(
			commits[13].output.value,
			(0.2 * consensus::GRIN_BASE as f64) as u64
		);
		assert_eq!(commits[14].output.value, 15 * consensus::GRIN_BASE);
		// change output is 3*reward - (88-35-3-0.2-15) - my_fees
		assert_eq!(
			commits[15].output.value,
			3 * consensus::REWARD
				- selection_args.sum_output_amounts()
				- my_fee_contribution(3, 6, 1, 1)?.fee()
		);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_contract_self_spend_custom_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_self_spend_custom_tx";
	setup(test_dir);
	contract_self_spend_custom_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
