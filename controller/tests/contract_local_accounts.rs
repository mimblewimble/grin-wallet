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

//! Contracts between accounts in one wallet
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_core::core::{Input, OutputFeatures};
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{ContractNewArgsAPI, ContractRevokeArgsAPI};
use libwallet::{Error, SlateState};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::thread;

#[macro_use]
mod common;

fn local_transfer(
	test_dir: &'static str,
	invoice: bool,
	early_lock: bool,
	revoke: bool,
) -> Result<(), Error> {
	let mut proxy = common::create_wallet_proxy(test_dir);
	let chain = proxy.chain.clone();
	let stopper = proxy.running.clone();
	let client = LocalWalletClient::new("wallet1", proxy.tx.clone());
	let (wallet, mask, _) =
		common::create_local_wallet(test_dir, "wallet1", None, client.clone(), true);
	proxy.add_wallet(
		"wallet1",
		client.get_send_instance(),
		wallet.clone(),
		mask.clone(),
	);
	let proxy_thread = thread::spawn(move || proxy.run().unwrap());
	let mask = mask.as_ref();
	let result =
		common::owner_single_use(wallet.clone(), mask, PathBuf::from(test_dir), |api, m| {
			for account in ["default", "receiver", "unrelated"] {
				if account != "default" {
					api.create_account_path(m, account)?;
				}
				api.set_active_account(m, account)?;
				test_framework::award_blocks_to_wallet(&chain, wallet.clone(), m, 4, false)?;
			}
			let amount = 5_000_000_000;
			let (initiator, counterparty) = if invoice {
				("receiver", "default")
			} else {
				("default", "receiver")
			};
			let change = if invoice { amount } else { -amount };
			api.set_active_account(m, "unrelated")?;
			let (_, unrelated) = api.retrieve_outputs(m, false, true, None)?;
			let unrelated = unrelated.first().unwrap().clone();
			api.set_active_account(m, initiator)?;
			let mut args = common::contract_setup_args(Some(change));
			args.add_outputs = early_lock;
			let first = api.contract_new(
				m,
				&ContractNewArgsAPI {
					setup_args: args,
					ttl_blocks: Some(20),
				},
			)?;
			// Preserve the legacy context key
			let initiator_parent = {
				wallet_inst!(wallet, w);
				let ctx = w.get_private_context(m, first.id.as_bytes())?;
				ctx.parent_key_id
			};

			// Setup retries stay with the original account
			api.set_active_account(m, "unrelated")?;
			{
				wallet_inst!(wallet, w);
				let retried = libwallet::contract::setup(
					w,
					m,
					&first,
					&common::contract_setup_args(Some(change)),
				)?;
				assert_eq!(retried.participant_data.len(), 1);
				assert_eq!(w.private_context_iter()?.count(), 1);
				assert_eq!(
					w.get_private_context(m, first.id.as_bytes())?.parent_key_id,
					initiator_parent
				);
			}
			let mut sign_args = common::contract_setup_args(Some(-change));
			api.set_active_account(m, if invoice { "unrelated" } else { counterparty })?;
			if invoice {
				sign_args.src_acct_name = Some(counterparty.into());
			}
			let second = common::roundtrip_slate(&api.contract_sign(m, &first, &sign_args)?, 4)?;
			{
				wallet_inst!(wallet, w);
				assert_eq!(
					w.get_private_context(m, first.id.as_bytes())?.parent_key_id,
					initiator_parent
				);
				assert_eq!(w.private_context_iter()?.count(), 2);
			}
			api.set_active_account(m, counterparty)?;
			let counterparty_tx = common::tx_log_for_slate(api, m, &second)?;
			let progress = common::wallet_progress(api, m)?;
			// Reject replay of both messages
			for slate in [&first, &second] {
				let err = api.contract_sign(m, slate, &sign_args).unwrap_err();
				assert!(
					matches!(err, Error::GenericError(ref msg) if msg.contains("already been signed"))
				);
			}
			assert_eq!(common::wallet_progress(api, m)?, progress);
			assert_eq!(
				api.contract_view(m, &second)?.agreed_net_change,
				Some(-change)
			);

			api.set_active_account(m, "unrelated")?;
			assert!(api.contract_view(m, &second).is_err());
			assert!(api
				.contract_sign(m, &second, &common::contract_setup_args(None))
				.is_err());
			api.set_active_account(m, initiator)?;
			assert_eq!(
				api.contract_view(m, &second)?.agreed_net_change,
				Some(change)
			);
			let progress = common::wallet_progress(api, m)?;
			// Reject inputs from unrelated accounts
			let mut tampered = second.clone();
			tampered.tx = Some(
				tampered
					.tx_or_err()?
					.clone()
					.with_input(Input::new(OutputFeatures::Coinbase, unrelated.commit)),
			);
			let err = api
				.contract_sign(m, &tampered, &common::contract_setup_args(None))
				.unwrap_err();
			assert!(
				matches!(err, Error::GenericError(ref msg) if msg.contains("unexpected input commitment"))
			);
			assert_eq!(common::wallet_progress(api, m)?, progress);

			// Require the counterparty's signature
			let mut unsigned = second.clone();
			for participant in &mut unsigned.participant_data {
				participant.part_sig = None;
			}
			let err = api
				.contract_sign(m, &unsigned, &common::contract_setup_args(None))
				.unwrap_err();
			assert!(
				matches!(err, Error::GenericError(ref msg) if msg.contains("unexpected input"))
			);
			assert_eq!(common::wallet_progress(api, m)?, progress);

			if revoke {
				let initiator_tx = common::tx_log_for_slate(api, m, &second)?;
				// Revoking one party preserves the other context
				let replacement = api
					.contract_revoke(
						m,
						&ContractRevokeArgsAPI {
							tx_id: counterparty_tx.id,
							src_acct_name: Some(counterparty.into()),
						},
					)?
					.unwrap();
				{
					wallet_inst!(wallet, w);
					assert_eq!(
						w.get_private_context(m, first.id.as_bytes())?.parent_key_id,
						initiator_parent
					);
					assert_eq!(w.private_context_iter()?.count(), 1);
				}
				assert!(api
					.contract_revoke(
						m,
						&ContractRevokeArgsAPI {
							tx_id: counterparty_tx.id,
							src_acct_name: Some(counterparty.into()),
						}
					)?
					.is_none());
				// Revoked contributions are no longer authorized
				assert!(api
					.contract_sign(m, &second, &common::contract_setup_args(None))
					.is_err());
				let other_replacement = api
					.contract_revoke(
						m,
						&ContractRevokeArgsAPI {
							tx_id: initiator_tx.id,
							src_acct_name: Some(initiator.into()),
						},
					)?
					.unwrap();
				assert_ne!(replacement.id, other_replacement.id);
				wallet_inst!(wallet, w);
				assert_eq!(w.private_context_iter()?.count(), 0);
				return Ok(());
			}

			let final_slate = api.contract_sign(m, &second, &common::contract_setup_args(None))?;
			assert_eq!(
				final_slate.state,
				if invoice {
					SlateState::Invoice3
				} else {
					SlateState::Standard3
				}
			);
			{
				wallet_inst!(wallet, w);
				assert!(matches!(
					w.get_private_context(m, first.id.as_bytes()),
					Err(Error::NotFoundErr(_))
				));
				assert_eq!(w.private_context_iter()?.count(), 1);
			}
			// Reject signing again even after context deletion
			for (account, net) in [(initiator, change), (counterparty, -change)] {
				api.set_active_account(m, account)?;
				for slate in [&first, &second] {
					assert!(api
						.contract_sign(m, slate, &common::contract_setup_args(Some(net)))
						.is_err());
				}
				let view = api.contract_view(m, &final_slate)?;
				assert_eq!(view.agreed_net_change, Some(net));
				assert_eq!(
					view.own_commitment_status,
					libwallet::contract::types::OwnCommitmentStatus::Unknown
				);
			}
			// Mine rewards into a third account to isolate transfer balances
			api.set_active_account(m, "unrelated")?;
			assert!(api.contract_view(m, &final_slate).is_err());
			api.post_tx(m, &final_slate, false)?;
			let fee = my_fee_contribution(1, 1, 1, 2)?.fee();
			for (account, net) in [("default", -amount), ("receiver", amount)] {
				api.set_active_account(m, account)?;
				let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
				assert!(refreshed);
				assert_eq!(
					info.total,
					(4 * grin_core::consensus::REWARD as i64 + net) as u64 - fee
				);
				assert!(common::tx_log_for_slate(api, m, &final_slate)?.confirmed);
			}
			Ok(())
		});
	stopper.store(false, Ordering::Relaxed);
	proxy_thread.join().unwrap();
	result
}

#[test]
fn contracts_between_local_accounts() -> Result<(), Error> {
	for (dir, invoice, early) in [
		("test_output/contract_local_srs", false, false),
		("test_output/contract_local_srs_early", false, true),
		("test_output/contract_local_rsr", true, false),
		("test_output/contract_local_rsr_early", true, true),
	] {
		common::setup(dir);
		local_transfer(dir, invoice, early, false)?;
		common::clean_output_dir(dir);
	}
	Ok(())
}

#[test]
fn revoke_local_counterparty() -> Result<(), Error> {
	let test_dir = "test_output/contract_local_revoke";
	common::setup(test_dir);
	local_transfer(test_dir, false, true, true)?;
	common::clean_output_dir(test_dir);
	Ok(())
}
