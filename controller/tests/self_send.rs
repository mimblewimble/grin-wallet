// Copyright 2021 The Grin Developers
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

//! Transfers within and between wallets
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use easy_jsonrpc_mw::Handler;
use grin_core::consensus::REWARD;
use grin_wallet_api::OwnerRpc;
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::slate_versions::{SlateVersion, VersionedSlate};
use libwallet::{InitTxArgs, IssueInvoiceTxArgs, SlateState, TxLogEntryType};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

#[macro_use]
mod common;
use common::{clean_output_dir, setup};

fn rpc(api: &(dyn OwnerRpc + 'static), method: &str, params: Value) -> Value {
	let response = api
		.handle_request(json!({
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params
		}))
		.as_option()
		.unwrap();
	assert!(
		response["error"].is_null() && response["result"]["Err"].is_null(),
		"{}",
		response
	);
	response["result"]["Ok"].clone()
}

#[derive(Clone, Copy, PartialEq)]
enum Case {
	Complete,
	Sync,
	Cancel,
	Expire,
	SyncCancel,
}

fn with_proxy(
	run: impl FnOnce() -> Result<(), libwallet::Error> + Send,
	stopper: Arc<AtomicBool>,
	test: impl FnOnce() -> Result<(), libwallet::Error>,
) -> Result<(), libwallet::Error> {
	thread::scope(|scope| {
		let worker = scope.spawn(run);
		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
		stopper.store(false, Ordering::Relaxed);
		worker.join().unwrap()?;
		result.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
	})
}

fn transfer(
	dir: &str,
	source: &str,
	dest: &str,
	invoice: bool,
	separate: bool,
	case: Case,
) -> Result<(), libwallet::Error> {
	let mut proxy: test_framework::WalletProxy<'static, _, _, _> =
		test_framework::WalletProxy::new(dir);
	let chain = proxy.chain.clone();
	let stopper = proxy.running.clone();
	create_wallet_and_add!(client1, wallet1, mask1, dir, "wallet1", None, &mut proxy, false, api1);
	create_wallet_and_add!(client2, wallet2, mask2, dir, "wallet2", None, &mut proxy, false, api2);
	let receiver = if separate { &api2 } else { &api1 };
	let receiver_wallet = if separate {
		wallet2.clone()
	} else {
		wallet1.clone()
	};
	with_proxy(
		move || proxy.run(),
		stopper,
		|| {
			let cancel = matches!(case, Case::Cancel | Case::Expire | Case::SyncCancel);
			for api in [&api1, &api2] {
				for account in ["a", "b", "mining"] {
					api.create_account_path(None, account)?;
				}
			}
			api1.set_active_account(None, source)?;
			test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), None, 10, false)?;
			let (_, before) = api1.retrieve_summary_info(None, true, 1)?;
			receiver.set_active_account(None, dest)?;
			let address = receiver.get_slatepack_address(None, 0)?;
			api1.set_active_account(None, "mining")?;
			let expires = case == Case::Expire;
			let mut args = InitTxArgs {
				src_acct_name: Some(source.into()),
				amount: REWARD * 2,
				minimum_confirmations: if invoice && source == dest { 0 } else { 1 },
				ttl_blocks: if expires { Some(1) } else { None },
				payment_proof_recipient_address: if invoice { None } else { Some(address) },
				..Default::default()
			};
			let mut slate = if invoice {
				receiver.issue_invoice_tx(
					None,
					IssueInvoiceTxArgs {
						dest_acct_name: Some(dest.into()),
						amount: args.amount,
						..Default::default()
					},
				)?
			} else {
				api1.init_send_tx(None, args.clone())?
			};
			let pack = api1.create_slatepack_message(None, &slate, None, vec![])?;
			slate = receiver.slate_from_slatepack_message(None, pack, vec![0])?;
			let sync_fail = matches!(case, Case::Sync | Case::SyncCancel);
			if sync_fail {
				api1.set_tor_config(Some(grin_wallet_config::TorConfig {
					use_integrated: Some(false),
					socks_proxy_addr: "invalid".into(),
					..Default::default()
				}))?;
				args.send_args = Some(libwallet::InitTxSendArgs {
					dest: receiver.get_slatepack_address(None, 0)?.to_string(),
					post_tx: false,
					fluff: false,
					skip_tor: None,
				});
			}
			let original = slate.clone();
			if invoice {
				slate = api1.process_invoice_tx(None, &slate, args.clone())?;
				assert!(matches!(
					api1.process_invoice_tx(None, &original, args.clone()),
					Err(libwallet::Error::TransactionAlreadyReceived(_))
				));
				if !sync_fail {
					api1.tx_lock_outputs(None, &slate)?;
				}
			} else {
				api1.tx_lock_outputs(None, &slate)?;
				wallet::controller::foreign_single_use(
					receiver_wallet.clone(),
					PathBuf::from(dir),
					None,
					|api| {
						let received = api.receive_tx(&slate, Some(dest), None)?;
						assert!(api.receive_tx(&slate, Some(dest), None).is_err());
						assert!(api.receive_tx(&slate, Some("mining"), None).is_err());
						slate = received;
						Ok(())
					},
				)?;
			}
			assert!(api1.tx_lock_outputs(None, &slate).is_err());
			let (from, from_account, to, to_account) = if invoice {
				(&api1, source, receiver, dest)
			} else {
				(receiver, dest, &api1, source)
			};
			to.set_active_account(None, to_account)?;
			let address = to.get_slatepack_address(None, 0)?;
			from.set_active_account(None, from_account)?;
			let pack = from.create_slatepack_message(None, &slate, Some(0), vec![address])?;
			to.set_active_account(None, to_account)?;
			slate = to.slate_from_slatepack_message(None, pack, vec![0])?;
			if cancel {
				assert!(api1.cancel_tx(None, None, None).is_err());
				if expires {
					api1.set_active_account(None, "mining")?;
					test_framework::award_blocks_to_wallet(
						&chain,
						wallet1.clone(),
						None,
						1,
						false,
					)?;
					api1.set_active_account(None, source)?;
					api1.retrieve_summary_info(None, true, 1)?;
				} else {
					api1.set_active_account(None, source)?;
					api1.cancel_tx(None, None, Some(slate.id))?;
				}
				if separate {
					receiver.set_active_account(None, dest)?;
					receiver.cancel_tx(None, None, Some(slate.id))?;
				}
				api1.close_wallet(None)?;
				api1.open_wallet(None, "".into(), false)?;
				for (api, account) in [(&api1, source), (receiver, dest)] {
					api.set_active_account(None, account)?;
					let (_, entries) = api.retrieve_txs(None, false, None, Some(slate.id), None)?;
					assert_eq!(
						entries.len(),
						if !separate && source == dest { 2 } else { 1 }
					);
					assert!(entries.iter().all(|t| matches!(
						t.tx_type,
						TxLogEntryType::TxSentCancelled | TxLogEntryType::TxReceivedCancelled
					)));
					assert!(api.finalize_tx(None, &slate).is_err());
				}
				api1.set_active_account(None, source)?;
				let (_, info) = api1.retrieve_summary_info(None, true, 1)?;
				assert_eq!(info.total, before.total);
				assert_eq!(info.amount_locked, 0);
				if !invoice {
					wallet::controller::foreign_single_use(
						receiver_wallet.clone(),
						PathBuf::from(dir),
						None,
						|api| {
							let error = api.receive_tx(&original, Some(dest), None).unwrap_err();
							if expires {
								assert_eq!(error, libwallet::Error::TransactionExpired);
							} else {
								assert!(matches!(
									error,
									libwallet::Error::TransactionWasCancelled(_)
								));
							}
							Ok(())
						},
					)?;
				}
				return Ok(());
			}
			if invoice && separate {
				assert!(receiver.tx_lock_outputs(None, &slate).is_err());
			}
			let finalizer = if invoice { receiver } else { &api1 };
			finalizer.set_active_account(None, "mining")?;
			let mut invalid = slate.clone();
			invalid.state = SlateState::Standard1;
			assert!(finalizer.finalize_tx(None, &invalid).is_err());
			let result = rpc(
				finalizer,
				"finalize_tx",
				json!({
					"token": null, "slate": VersionedSlate::into_version(slate, SlateVersion::V4)?
				}),
			);
			slate = serde_json::from_value::<VersionedSlate>(result)
				.unwrap()
				.into();
			let fee = slate.fee_fields.fee();
			assert!(finalizer.finalize_tx(None, &slate).is_err());
			let state = if invoice {
				SlateState::Invoice3
			} else {
				SlateState::Standard3
			};
			assert_eq!(slate.state, state);
			let stored = finalizer
				.get_stored_tx(None, None, Some(&slate.id))?
				.unwrap();
			assert_eq!(stored.tx, slate.tx);
			api1.set_active_account(None, "mining")?;
			api1.post_tx(None, &slate, false)?;
			test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), None, 3, false)?;
			api1.set_active_account(None, source)?;
			let (_, sent) = api1.retrieve_summary_info(None, true, 1)?;
			let same = !separate && source == dest;
			assert_eq!(
				sent.total,
				before.total - fee - if same { 0 } else { REWARD * 2 }
			);
			receiver.set_active_account(None, dest)?;
			let (_, received) = receiver.retrieve_summary_info(None, true, 1)?;
			assert_eq!(received.total, if same { sent.total } else { REWARD * 2 });
			for (api, account, kind) in [
				(&api1, source, TxLogEntryType::TxSent),
				(receiver, dest, TxLogEntryType::TxReceived),
			] {
				api.set_active_account(None, account)?;
				let result = rpc(
					api,
					"retrieve_txs",
					json!({
						"token": null, "refresh_from_node": false, "tx_id": null, "tx_slate_id": slate.id
					}),
				);
				let entries: Vec<libwallet::TxLogEntry> =
					serde_json::from_value(result[1].clone()).unwrap();
				assert_eq!(entries.len(), if same { 2 } else { 1 });
				let entry = entries.iter().find(|t| t.tx_type == kind).unwrap();
				assert!(entry.confirmed);
				assert_eq!(entry.tx_slate_id, Some(slate.id));
				if kind == TxLogEntryType::TxSent {
					assert_eq!(entry.fee, Some(slate.fee_fields));
				}
				assert!(api.cancel_tx(None, Some(entry.id), None).is_err());
				if !separate
					|| (kind == TxLogEntryType::TxSent && !invoice)
					|| (kind == TxLogEntryType::TxReceived && invoice)
				{
					assert_eq!(
						api.get_stored_tx(None, Some(entry.id), None)?.unwrap().tx,
						slate.tx
					);
				}
				if kind == TxLogEntryType::TxSent && !invoice {
					let proof = api.retrieve_payment_proof(None, false, Some(entry.id), None)?;
					let by_uuid = api.retrieve_payment_proof(None, false, None, Some(slate.id))?;
					assert_eq!(proof.excess, by_uuid.excess);
					assert_eq!(api.verify_payment_proof(None, &proof)?, (true, !separate));
				}
			}

			for instance in [&wallet1, &receiver_wallet] {
				let mut lock = instance.lock();
				let w = lock.lc_provider()?.wallet_inst()?;
				for output in w.iter()? {
					assert_eq!(output.root_key_id, output.key_id.parent_path());
				}
			}
			finalizer.close_wallet(None)?;
			finalizer.open_wallet(None, "".into(), false)?;
			let stored = finalizer
				.get_stored_tx(None, None, Some(&slate.id))?
				.unwrap();
			assert_eq!(stored.tx, slate.tx);
			Ok(())
		},
	)
}

fn cases(dir: &str, invoice: bool, separate: bool, cancel: bool) {
	setup(dir);
	for (source, dest) in [
		("default", "default"),
		("a", "a"),
		("default", "a"),
		("a", "default"),
		("a", "b"),
		("b", "a"),
	] {
		let path = format!("{}/{}_{}", dir, source, dest);
		transfer(
			&path,
			source,
			dest,
			invoice,
			separate,
			if cancel { Case::Cancel } else { Case::Complete },
		)
		.unwrap();
	}
	clean_output_dir(dir);
}

#[test]
fn self_send() {
	cases("test_output/self_send", false, false, false);
}

#[test]
fn self_invoice() {
	cases("test_output/self_invoice", true, false, false);
}

#[test]
fn send() {
	cases("test_output/send", false, true, false);
}

#[test]
fn invoice() {
	cases("test_output/invoice", true, true, false);
}

#[test]
fn cancel() {
	for invoice in [false, true] {
		for separate in [false, true] {
			cases(
				&format!("test_output/cancel_{}_{}", invoice, separate),
				invoice,
				separate,
				true,
			);
		}
	}
}

#[test]
fn sync_fail() {
	let dir = "test_output/self_sync_fail";
	setup(dir);
	for separate in [false, true] {
		for (name, case) in [("send", Case::Sync), ("cancel", Case::SyncCancel)] {
			let path = format!("{}/{}_{}", dir, separate, name);
			transfer(&path, "b", "a", true, separate, case).unwrap();
		}
	}
	clean_output_dir(dir);
}

#[test]
fn expiry() {
	let dir = "test_output/self_expiry";
	setup(dir);
	transfer(dir, "a", "a", false, false, Case::Expire).unwrap();
	clean_output_dir(dir);
}
