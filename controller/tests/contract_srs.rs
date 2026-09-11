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

//! Test a wallet doing contract SRS flow
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use grin_core::core::transaction::{CommitWrapper, Input, Inputs, OutputFeatures, Transaction};
use grin_util::secp::Signature;
use impls::test_framework::{self};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI, OwnCommitmentStatus};
use libwallet::{NodeVersionInfo, Slate, SlateState, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};
use std::path::PathBuf;

fn reject_contract_slate(
	method: grin_wallet_api::ForeignCheckMiddlewareFn,
	_node_version: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	assert!(matches!(
		method,
		grin_wallet_api::ForeignCheckMiddlewareFn::ContractSign
	));
	assert!(slate.is_some());
	Err(libwallet::Error::GenericError(
		"Contract rejected by middleware".to_string(),
	))
}

fn assert_participant_error(err: libwallet::Error, count: u8) {
	assert!(matches!(
		err,
		libwallet::Error::GenericError(ref msg)
			if msg == &format!(
				"Unsupported num_participants: {} (expected 1 or 2)",
				count
			)
	));
}

/// contract SRS flow
fn contract_srs_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create two wallets and mine 4 blocks in each (we want both to have balance to get a payjoin)
	let (wallets, chain, stopper, mut bh) =
		create_wallets(vec![vec![("default", 4)], vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();
	let recv_wallet = wallets[1].0.clone();
	let recv_mask = wallets[1].1.as_ref();
	let participant_fee = my_fee_contribution(1, 1, 1, 2)?.fee();
	let receiver_rate = 2 * u32::try_from(grin_core::global::get_accept_fee_base()).unwrap();
	let receiver_fee = Transaction::weight_by_iok(1, 1, 0) * u64::from(receiver_rate)
		+ (Transaction::weight_by_iok(0, 0, 1) * u64::from(receiver_rate)).div_ceil(2);
	let ttl_cutoff = bh + 20;
	let ttl_error = format!(
		"Contract TTL changed from {} to {}",
		ttl_cutoff,
		ttl_cutoff + 1
	);

	let mut slate = Slate::blank(0, false); // this gets overriden below

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Send wallet inititates a standard transaction with --send=5
			let mut args = ContractNewArgsAPI {
				ttl_blocks: Some(20),
				setup_args: ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(-5_000_000_000),
					..Default::default()
				},
				..Default::default()
			};
			let progress = common::wallet_progress(api, m)?;
			for count in [0, 3] {
				args.setup_args.num_participants = count;
				let err = api.contract_new(m, &mut args).unwrap_err();
				assert_participant_error(err, count);
			}
			assert_eq!(common::wallet_progress(api, m)?, progress);

			args.setup_args.num_participants = 2;
			args.ttl_blocks = Some(0);
			let err = api.contract_new(m, &mut args).unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Contract TTL must be at least 1 block"
			));
			args.ttl_blocks = Some(20);
			args.setup_args.fee_rate = Some(0);
			let err = api.contract_new(m, &mut args).unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Contract fee rate must be at least 1"
			));
			args.setup_args.fee_rate = None;
			assert_eq!(common::wallet_progress(api, m)?, progress);
			slate = api.contract_new(m, &mut args)?;
			let tx_log = common::tx_log_for_slate(api, m, &slate)?;
			assert_eq!(tx_log.ttl_cutoff_height, Some(ttl_cutoff));
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard1);
	assert_eq!(slate.ttl_cutoff_height, ttl_cutoff);
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
			let progress = common::wallet_progress(api, m)?;
			let setup_args = ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				net_change: Some(-5_000_000_000),
				..Default::default()
			};
			for count in [0, 3] {
				let mut invalid = slate.clone();
				invalid.num_participants = count;
				let err = {
					let mut owner = api.wallet_inst.lock();
					let wallet = owner.lc_provider()?.wallet_inst()?;
					libwallet::contract::setup(wallet, m, &invalid, &setup_args).unwrap_err()
				};
				assert_participant_error(err, count);
			}
			assert_eq!(common::wallet_progress(api, m)?, progress);

			let mut mismatched = setup_args.clone();
			mismatched.num_participants = 1;
			let err = {
				let mut owner = api.wallet_inst.lock();
				let wallet = owner.lc_provider()?.wallet_inst()?;
				libwallet::contract::setup(wallet, m, &slate, &mismatched).unwrap_err()
			};
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Inconsistent num_participants. Slate num_participants:2, Setup num_participants: 1"
			));
			assert_eq!(common::wallet_progress(api, m)?, progress);

			let mut invalid = slate.clone();
			invalid.participant_data[0].part_sig =
				Some(Signature::from_raw_data(&[0; 64]).unwrap());
			let err = {
				let mut owner = api.wallet_inst.lock();
				let wallet = owner.lc_provider()?.wallet_inst()?;
				libwallet::contract::setup(wallet, m, &invalid, &setup_args).unwrap_err()
			};
			assert!(matches!(err, libwallet::Error::LibTX(_)));
			assert_eq!(common::wallet_progress(api, m)?, progress);
			Ok(())
		},
	)?;

	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let progress = common::wallet_progress(api, m)?;
			for count in [0, 3] {
				let mut invalid = slate.clone();
				invalid.num_participants = count;
				let err = match api.contract_view(m, &invalid) {
					Err(err) => err,
					Ok(_) => panic!("invalid participant count accepted"),
				};
				assert_participant_error(err, count);
				let err = api
					.contract_sign(
						m,
						&invalid,
						&ContractSetupArgsAPI {
							selection_args: common::contract_selection_args(),
							net_change: Some(5_000_000_000),
							..Default::default()
						},
					)
					.unwrap_err();
				assert_participant_error(err, count);
			}
			assert_eq!(common::wallet_progress(api, m)?, progress);

			let mut invalid = slate.clone();
			invalid.state = SlateState::Unknown;
			let err = api
				.contract_sign(
					m,
					&invalid,
					&ContractSetupArgsAPI {
						selection_args: common::contract_selection_args(),
						net_change: Some(5_000_000_000),
						..Default::default()
					},
				)
				.unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Cannot advance a contract slate in state UN"
			));
			assert_eq!(common::wallet_progress(api, m)?, progress);

			let wrong_args = ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				net_change: Some(-5_000_000_000),
				..Default::default()
			};
			let err = api.contract_sign(m, &slate, &wrong_args).unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Expected net change 5000000000, got -5000000000 (did you mean --receive instead of --send?)"
			));

			Ok(())
		},
	)?;

	// Receive wallet signs through the foreign API.
	let args = ContractSetupArgsAPI {
		selection_args: common::contract_selection_args(),
		net_change: Some(5_000_000_000),
		fee_rate: Some(receiver_rate),
		..Default::default()
	};
	let incoming = slate.clone();
	{
		let api = grin_wallet_api::Foreign::new(
			recv_wallet.clone(),
			PathBuf::from(test_dir),
			recv_mask.cloned(),
			Some(reject_contract_slate),
			false,
		);
		let err = api.contract_sign(&incoming, &args).unwrap_err();
		assert!(matches!(
			err,
			libwallet::Error::GenericError(ref msg)
				if msg == "Contract rejected by middleware"
		));
	}
	wallet::controller::foreign_single_use(
		recv_wallet.clone(),
		PathBuf::from(test_dir),
		recv_mask.cloned(),
		|api| {
			let rejected = ContractSetupArgsAPI {
				net_change: Some(-5_000_000_000),
				..args.clone()
			};
			let err = api.contract_sign(&incoming, &rejected).unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == "Can't sign a non-receiving contract from a foreign API."
			));
			slate = api.contract_sign(&incoming, &args)?;
			Ok(())
		},
	)?;

	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let progress = common::wallet_progress(api, m)?;
			let err = api.contract_sign(m, &incoming, &args).unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == &format!("Slate with id:{} has already been signed.", incoming.id)
			));
			assert_eq!(common::wallet_progress(api, m)?, progress);

			let err = {
				let mut owner = api.wallet_inst.lock();
				let wallet = owner.lc_provider()?.wallet_inst()?;
				libwallet::contract::setup(wallet, m, &slate, &args).unwrap_err()
			};
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg)
					if msg == &format!("Slate with id:{} has already been signed.", slate.id)
			));
			assert_eq!(common::wallet_progress(api, m)?, progress);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard2);
	assert_eq!(slate.ttl_cutoff_height, ttl_cutoff);
	common::assert_basic_contract_slate(
		&slate,
		common::ExpectedContractSlate {
			amount: 5_000_000_000,
			fee: participant_fee + receiver_fee,
			inputs: 1,
			coinbase_inputs: 1,
			outputs: 1,
			kernels: 1,
			num_participants: 2,
			participant_data: 2,
			signatures: 1,
		},
	);
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let view = api.contract_view(m, &slate)?;
			assert_eq!(view.own_commitment_status, OwnCommitmentStatus::Clean);
			assert_eq!(view.own_fee, Some(receiver_fee));
			assert_eq!(
				view.balance_change,
				Some(5_000_000_000 - receiver_fee as i64)
			);
			Ok(())
		},
	)?;
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let view = api.contract_view(m, &slate)?;
			assert_eq!(view.own_commitment_status, OwnCommitmentStatus::Clean);
			assert_eq!(view.own_fee, Some(participant_fee));
			assert_eq!(
				view.balance_change,
				Some(-5_000_000_000 - participant_fee as i64)
			);
			let mut no_tx = slate.clone();
			no_tx.tx = None;
			let view = api.contract_view(m, &no_tx)?;
			assert_eq!(view.own_commitment_status, OwnCommitmentStatus::Unknown);
			Ok(())
		},
	)?;

	// The sender must reject an unused commitment from its wallet if it was inserted by the receiver.
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, outputs) = api.retrieve_outputs(m, false, false, None)?;
			let tx = slate.tx_or_err()?;
			let input_commits = Vec::<CommitWrapper>::from(&tx.inputs());
			let progress = common::wallet_progress(api, m)?;
			let mut changed = slate.clone();
			changed.tx = Some(
				Transaction::new(
					Inputs::CommitOnly(input_commits.clone()),
					tx.outputs(),
					tx.kernels(),
				)
				.with_offset(tx.offset.clone()),
			);
			let err = api
				.contract_sign(m, &changed, &ContractSetupArgsAPI::default())
				.unwrap_err();
			match err {
				libwallet::Error::GenericError(message) => {
					assert_eq!(message, "Contract slate input features are missing")
				}
				err => panic!("unexpected error: {}", err),
			}
			let view = api.contract_view(m, &changed)?;
			assert_eq!(view.own_commitment_status, OwnCommitmentStatus::Unknown);
			assert_eq!(common::wallet_progress(api, m)?, progress);

			let (output, pos) = outputs
				.iter()
				.find_map(|output| {
					let unused = !input_commits
						.iter()
						.any(|input| input.commitment() == output.commit)
						&& !tx
							.outputs()
							.iter()
							.any(|tx_output| tx_output.commitment() == output.commit);
					if unused {
						chain
							.get_output_pos(&output.commit)
							.ok()
							.map(|pos| (output, pos))
					} else {
						None
					}
				})
				.expect("sender has an unused confirmed output");
			let features = if output.output.is_coinbase {
				OutputFeatures::Coinbase
			} else {
				OutputFeatures::Plain
			};
			let mut changed = slate.clone();
			changed.tx = Some(
				changed
					.tx_or_err()?
					.clone()
					.with_input(Input::new(features, output.commit)),
			);
			let view = api.contract_view(m, &changed)?;
			assert_eq!(
				view.own_commitment_status,
				OwnCommitmentStatus::UnexpectedInput
			);
			let err = api
				.contract_sign(m, &changed, &ContractSetupArgsAPI::default())
				.unwrap_err();
			match err {
				libwallet::Error::GenericError(message) => assert_eq!(
					message,
					"Contract slate contains an unexpected input commitment from this wallet"
				),
				err => panic!("unexpected error: {}", err),
			}

			let mut changed = slate.clone();
			changed.tx = Some(
				changed
					.tx_or_err()?
					.clone()
					.with_output(chain.get_unspent_output_at(pos).unwrap()),
			);
			let view = api.contract_view(m, &changed)?;
			assert_eq!(
				view.own_commitment_status,
				OwnCommitmentStatus::UnexpectedOutput
			);
			let err = api
				.contract_sign(m, &changed, &ContractSetupArgsAPI::default())
				.unwrap_err();
			match err {
				libwallet::Error::GenericError(message) => assert_eq!(
					message,
					"Contract slate contains an unexpected output commitment from this wallet"
				),
				err => panic!("unexpected error: {}", err),
			}

			let mut changed = slate.clone();
			changed.tx = Some(
				changed
					.tx_or_err()?
					.clone()
					.with_input(Input::new(features, output.commit))
					.with_output(chain.get_unspent_output_at(pos).unwrap()),
			);
			let view = api.contract_view(m, &changed)?;
			assert_eq!(
				view.own_commitment_status,
				OwnCommitmentStatus::UnexpectedInputAndOutput
			);
			let err = api
				.contract_sign(m, &changed, &ContractSetupArgsAPI::default())
				.unwrap_err();
			match err {
				libwallet::Error::GenericError(message) => assert_eq!(
					message,
					"Contract slate contains unexpected input and output commitments from this wallet"
				),
				err => panic!("unexpected error: {}", err),
			}
			Ok(())
		},
	)?;

	// Send wallet finalizes and posts
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let progress = common::wallet_progress(api, m)?;
			let mut expired = slate.clone();
			expired.ttl_cutoff_height = bh;
			let err = api
				.contract_sign(m, &expired, &ContractSetupArgsAPI::default())
				.unwrap_err();
			assert!(matches!(err, libwallet::Error::TransactionExpired));

			let mut changed = slate.clone();
			changed.ttl_cutoff_height += 1;
			let err = match api.contract_view(m, &changed) {
				Err(err) => err,
				Ok(_) => panic!("changed contract TTL accepted"),
			};
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg) if msg == &ttl_error
			));
			let err = api
				.contract_sign(m, &changed, &ContractSetupArgsAPI::default())
				.unwrap_err();
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg) if msg == &ttl_error
			));
			assert_eq!(common::wallet_progress(api, m)?, progress);
			let args = &mut ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				..Default::default()
			};
			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard3);
	common::assert_basic_contract_slate(
		&slate,
		common::ExpectedContractSlate {
			amount: 5_000_000_000,
			fee: participant_fee + receiver_fee,
			inputs: 2,
			coinbase_inputs: 2,
			outputs: 2,
			kernels: 1,
			num_participants: 2,
			participant_data: 2,
			signatures: 2,
		},
	);
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let view = api.contract_view(m, &slate)?;
			assert_eq!(view.own_commitment_status, OwnCommitmentStatus::Clean);
			Ok(())
		},
	)?;
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let mut changed = slate.clone();
			changed.ttl_cutoff_height += 1;
			let err = match api.contract_view(m, &changed) {
				Err(err) => err,
				Ok(_) => panic!("changed contract TTL accepted"),
			};
			assert!(matches!(
				err,
				libwallet::Error::GenericError(ref msg) if msg == &ttl_error
			));
			let view = api.contract_view(m, &slate)?;
			assert_eq!(view.own_commitment_status, OwnCommitmentStatus::Unknown);
			assert_eq!(view.own_fee, Some(participant_fee));
			assert_eq!(
				view.balance_change,
				Some(-5_000_000_000 - participant_fee as i64)
			);
			Ok(())
		},
	)?;

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
			assert_eq!(tx_log.fee.map(|fee| fee.fee()), Some(receiver_fee));
			assert_eq!(
				wallet_info.amount_currently_spendable,
				4 * 60_000_000_000 + 5_000_000_000 - receiver_fee // we expect the balance of 4 mined blocks + 5 Grin - fees paid
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

	// Keep our fee when setup is retried with the original slate
	let sender_args = ContractSetupArgsAPI {
		selection_args: common::contract_selection_args(),
		net_change: Some(-1_000_000_000),
		..Default::default()
	};
	let receiver_args = ContractSetupArgsAPI {
		selection_args: common::contract_selection_args(),
		net_change: Some(1_000_000_000),
		..Default::default()
	};
	let incoming = {
		wallet_inst!(send_wallet, w);
		libwallet::contract::new(w, send_mask, &sender_args, None, None)?
	};
	let signed = {
		wallet_inst!(recv_wallet, w);
		let first = libwallet::contract::setup(w, recv_mask, &incoming, &receiver_args)?;
		let retried = libwallet::contract::setup(w, recv_mask, &incoming, &receiver_args)?;
		assert_eq!(retried.fee_fields, first.fee_fields);
		libwallet::contract::sign(w, recv_mask, &incoming, &receiver_args)?
	};
	{
		wallet_inst!(send_wallet, w);
		let signed = libwallet::contract::sign(w, send_mask, &signed, &sender_args)?;
		assert_eq!(signed.state, SlateState::Standard3);
	}

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_contract_srs_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_srs_tx";
	setup(test_dir);
	contract_srs_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
