// Copyright 2026 The Grin Developers
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

//! Background execution for wallet operations. Each operation runs on its
//! own thread with its own `Owner` handle over the shared wallet instance,
//! so slatepack workflows (which may attempt Tor round-trips) and long
//! scans never block the UI thread. Results come back over an mpsc channel
//! the UI drains each tick; scan/update progress arrives through the same
//! `StatusMessage` channel the CLI uses. The operation bodies mirror
//! `grin_wallet_controller::command` with terminal output replaced by
//! structured results.

use crate::tui::app::{SharedState, WalletView};
use grin_core::core::{amount_from_hr_string, amount_to_hr_string};
use grin_keychain as keychain;
use grin_util::secp::key::SecretKey;
use grin_util::Mutex;
use grin_wallet_api::{try_slatepack_sync_workflow, Owner};
use grin_wallet_config::{TorConfig, WalletConfig};
use grin_wallet_controller::controller;
use grin_wallet_controller::Error;
use grin_wallet_impls::PathToSlatepack;
use grin_wallet_impls::SlateGetter as _;
use grin_wallet_libwallet::api_impl::types::update_tx_slate_state;
use grin_wallet_libwallet::{
	sig_is_blank, InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, Slate, SlateState,
	SlatepackAddress, Slatepacker, SlatepackerArgs, StatusMessage, WalletInst, WalletLCProvider,
};
use qr_code::QrCode;
use serde_json as json;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

/// How often the dashboard refresher polls local wallet state
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

/// Messages sent to the UI thread
pub enum UiMsg {
	/// A fresh dashboard snapshot from the refresher
	View(Box<WalletView>),
	/// The outcome of a background operation
	Op(OpResult),
}

/// Outcome of a background operation, rendered by the UI
pub enum OpResult {
	/// A slatepack was produced: show it in the output modal
	Slatepack {
		title: String,
		lines: Vec<String>,
		armored: String,
		qr: Option<String>,
	},
	/// A multi-line text result
	Text {
		title: String,
		body: String,
		/// Text placed on the clipboard when the user presses 'c'
		copy: Option<String>,
	},
	/// A one-line notice shown as a dialog
	Info(String),
	/// A failure shown as a dialog
	Error(String),
	/// An invoice was parsed and needs user confirmation before payment
	ConfirmPay {
		amount: String,
		dest: String,
		params: PayParams,
		slate: Box<Slate>,
	},
}

/// Control messages for the refresher thread
pub enum RefreshCtrl {
	Now,
}

/// Everything a worker thread needs, cloned per operation
pub struct WorkerCtx<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	pub shared: Arc<SharedState>,
	pub ui_tx: mpsc::Sender<UiMsg>,
	pub status_tx: mpsc::Sender<StatusMessage>,
	pub wallet_config: WalletConfig,
	pub tor_config: TorConfig,
	pub tls_conf: Option<grin_api::TLSConfig>,
	pub api_secret: Option<String>,
	pub test_mode: bool,
	/// Path to grin-wallet.toml (required by Owner / foreign listener)
	pub config_path: PathBuf,
}

impl<L, C, K> Clone for WorkerCtx<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	fn clone(&self) -> Self {
		WorkerCtx {
			wallet_inst: self.wallet_inst.clone(),
			shared: self.shared.clone(),
			ui_tx: self.ui_tx.clone(),
			status_tx: self.status_tx.clone(),
			wallet_config: self.wallet_config.clone(),
			tor_config: self.tor_config.clone(),
			tls_conf: self.tls_conf.clone(),
			api_secret: self.api_secret.clone(),
			test_mode: self.test_mode,
			config_path: self.config_path.clone(),
		}
	}
}

/// Clears `busy` when dropped so panics and early returns cannot stick the UI.
struct BusyGuard {
	shared: Arc<SharedState>,
}

impl Drop for BusyGuard {
	fn drop(&mut self) {
		*self.shared.busy.lock() = None;
	}
}

/// Marks the shared state busy, runs `f` on a new thread with a fresh
/// `Owner` and the current keychain mask, and sends the result to the UI.
fn spawn_op<L, C, K, F>(ctx: &WorkerCtx<L, C, K>, name: &str, f: F)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
	F: FnOnce(
			&mut Owner<L, C, K>,
			Option<&SecretKey>,
			&WorkerCtx<L, C, K>,
		) -> Result<OpResult, Error>
		+ Send
		+ 'static,
{
	{
		let mut busy = ctx.shared.busy.lock();
		if let Some(current) = busy.as_ref() {
			let _ = ctx.ui_tx.send(UiMsg::Op(OpResult::Error(format!(
				"Another operation ('{}') is still in progress",
				current
			))));
			return;
		}
		*busy = Some(name.to_string());
	}
	let ctx = ctx.clone();
	let name = name.to_string();
	let shared = ctx.shared.clone();
	let ui_tx = ctx.ui_tx.clone();
	match thread::Builder::new()
		.name(format!("wallet-tui-{}", name))
		.spawn(move || {
			let _guard = BusyGuard {
				shared: ctx.shared.clone(),
			};
			let mut owner = Owner::new(
				ctx.wallet_inst.clone(),
				Some(ctx.status_tx.clone()),
				ctx.config_path.clone(),
			);
			let mask = ctx.shared.mask.lock().clone();
			let res = f(&mut owner, mask.as_ref(), &ctx);
			let msg = match res {
				Ok(r) => r,
				Err(e) => OpResult::Error(format!("{}", e)),
			};
			let _ = ctx.ui_tx.send(UiMsg::Op(msg));
		}) {
		Ok(_) => {}
		Err(e) => {
			*shared.busy.lock() = None;
			let _ = ui_tx.send(UiMsg::Op(OpResult::Error(format!(
				"Failed to start background operation '{}': {}",
				name, e
			))));
		}
	}
}

fn io_err(e: std::io::Error) -> Error {
	Error::GenericError(format!("I/O error: {}", e))
}

/// Where the slate comes from
pub enum SlateInput {
	File(String),
	Message(String),
}

/// Mirror of `command::parse_slatepack` without the stdin prompt path
fn parse_slate<L, C, K>(
	owner: &mut Owner<L, C, K>,
	mask: Option<&SecretKey>,
	input: &SlateInput,
) -> Result<(Slate, Option<SlatepackAddress>), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	match input {
		SlateInput::File(f) => {
			let dec_key = owner.get_slatepack_secret_key(mask, 0)?;
			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: Some(&dec_key),
			});
			let pts = PathToSlatepack::new(f.clone().into(), &packer, true);
			let slate = pts.get_tx()?.0;
			let sender = pts.get_slatepack(true)?.sender;
			Ok((slate, sender))
		}
		SlateInput::Message(m) => {
			let slate = owner.slate_from_slatepack_message(mask, m.clone(), vec![0])?;
			let slatepack = owner.decode_slatepack_message(mask, m.clone(), vec![0])?;
			Ok((slate, slatepack.sender))
		}
	}
}

/// Mirror of `command::output_slatepack`: encrypt/armor the slate, write
/// the .slatepack file, and build the output modal contents.
fn slatepack_output<L, C, K>(
	owner: &mut Owner<L, C, K>,
	mask: Option<&SecretKey>,
	slate: &Slate,
	dest: &str,
	outfile: Option<String>,
	lock: bool,
	finalizing: bool,
	title: &str,
) -> Result<OpResult, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let address = SlatepackAddress::try_from(dest).ok();
	// encrypt for recipient by default
	let recipients = match address.clone() {
		Some(a) => vec![a],
		None => vec![],
	};
	let message = owner.create_slatepack_message(mask, slate, Some(0), recipients)?;
	let tld = owner.get_top_level_directory()?;

	let slate_dir = format!("{}/{}", tld, "slatepack");
	let _ = std::fs::create_dir_all(&slate_dir);
	let out_file_name = match outfile {
		None => format!("{}/{}.{}.slatepack", slate_dir, slate.id, slate.state),
		Some(f) => f,
	};

	if lock {
		owner.tx_lock_outputs(mask, slate)?;
	}

	let mut output = File::create(&out_file_name).map_err(io_err)?;
	output.write_all(message.as_bytes()).map_err(io_err)?;
	output.sync_all().map_err(io_err)?;

	let mut lines = Vec::new();
	if finalizing {
		lines.push("Transaction finalized successfully.".to_string());
	} else {
		lines.push("Provide the slatepack below to the other party.".to_string());
	}
	lines.push(String::new());
	lines.push("Slatepack written to:".to_string());
	lines.push(format!("  {}", out_file_name));
	lines.push(String::new());
	if address.is_some() {
		lines.push("The slatepack data is encrypted for the recipient only.".to_string());
	} else {
		lines.push("The slatepack data is NOT encrypted.".to_string());
	}
	lines.push(String::new());
	lines.push("--- CUT BELOW THIS LINE ---".to_string());
	for l in message.lines() {
		lines.push(l.to_string());
	}
	lines.push("--- CUT ABOVE THIS LINE ---".to_string());

	let qr = QrCode::new(message.clone())
		.ok()
		.map(|q| q.to_string(false, 2));

	Ok(OpResult::Slatepack {
		title: title.to_string(),
		lines,
		armored: message,
		qr,
	})
}

/// Whether a Tor slatepack sync should be attempted (mirrors command.rs).
///
/// Pass `Some(true)` only when the user selected Manual; otherwise pass
/// `None` so a configured `skip_send_attempt` is still respected.
pub(crate) fn can_send_tor(tor_config: &TorConfig, manual: bool, test_mode: bool) -> bool {
	if test_mode {
		return false;
	}
	let skip_arg = if manual { Some(true) } else { None };
	tor_config.send_tor(skip_arg)
}

/// Parameters for a send, gathered from the form
pub struct SendParams {
	pub amount: String,
	pub dest: String,
	pub min_conf: u64,
	pub strategy_all: bool,
	pub change_outputs: u32,
	pub ttl_blocks: Option<u64>,
	pub fluff: bool,
	pub no_payment_proof: bool,
	pub manual: bool,
	pub amount_includes_fee: bool,
	pub estimate: bool,
	pub outfile: Option<String>,
}

pub fn spawn_send<L, C, K>(ctx: &WorkerCtx<L, C, K>, p: SendParams)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "send", move |owner, mask, ctx| {
		let use_max = p.amount.trim() == "max";
		// Match CLI: "max" implies the fee is included in the spendable amount.
		let amount_includes_fee = p.amount_includes_fee || use_max;
		let mut amount = match use_max {
			true => 0,
			false => amount_from_hr_string(p.amount.trim())
				.map_err(|e| Error::ArgumentError(format!("invalid amount: {}", e)))?,
		};
		if use_max {
			let (_, info) = owner.retrieve_summary_info(mask, true, p.min_conf)?;
			amount = info.amount_currently_spendable;
		}

		if p.estimate {
			let mut body = String::new();
			for strategy in ["smallest", "all"] {
				let init_args = InitTxArgs {
					amount,
					amount_includes_fee: Some(amount_includes_fee),
					minimum_confirmations: p.min_conf,
					max_outputs: 500,
					num_change_outputs: p.change_outputs,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					..Default::default()
				};
				match owner.init_send_tx(mask, init_args) {
					Ok(s) => body.push_str(&format!(
						"strategy '{}': amount {}, fee {}\n",
						strategy,
						amount_to_hr_string(s.amount, false),
						amount_to_hr_string(s.fee_fields.fee(), false),
					)),
					Err(e) => body.push_str(&format!("strategy '{}': {}\n", strategy, e)),
				}
			}
			return Ok(OpResult::Text {
				title: "Send Estimate".to_string(),
				body,
				copy: None,
			});
		}

		let payment_proof_address = match p.no_payment_proof {
			true => None,
			false => SlatepackAddress::try_from(p.dest.as_str()).ok(),
		};
		let init_args = InitTxArgs {
			amount,
			amount_includes_fee: Some(amount_includes_fee),
			minimum_confirmations: p.min_conf,
			max_outputs: 500,
			num_change_outputs: p.change_outputs,
			selection_strategy_is_use_all: p.strategy_all,
			payment_proof_recipient_address: payment_proof_address,
			ttl_blocks: p.ttl_blocks,
			send_args: None,
			..Default::default()
		};
		let slate = owner.init_send_tx(mask, init_args)?;

		if !can_send_tor(&ctx.tor_config, p.manual, ctx.test_mode) {
			return slatepack_output(
				owner,
				mask,
				&slate,
				&p.dest,
				p.outfile,
				true,
				false,
				"Send: Slatepack Created",
			);
		}

		let dest_addr = match SlatepackAddress::try_from(p.dest.as_str()) {
			Ok(a) => a,
			Err(_) => {
				return slatepack_output(
					owner,
					mask,
					&slate,
					&p.dest,
					p.outfile,
					true,
					false,
					"Send: Slatepack Created",
				);
			}
		};
		match try_slatepack_sync_workflow(
			&slate,
			&dest_addr,
			Some(ctx.tor_config.clone()),
			None,
			false,
		) {
			Ok(s) => {
				owner.tx_lock_outputs(mask, &s)?;
				let ret_slate = owner.finalize_tx(mask, &s)?;
				owner.post_tx(mask, &ret_slate, p.fluff)?;
				Ok(OpResult::Info(format!(
					"Sent {} grin to {} and posted the transaction successfully.",
					amount_to_hr_string(amount, false),
					p.dest
				)))
			}
			Err(_) => slatepack_output(
				owner,
				mask,
				&slate,
				&p.dest,
				p.outfile,
				true,
				false,
				"Send: Slatepack Created",
			),
		}
	});
}

/// Slate-consuming operations that share the paste/file input flow
pub enum SlateOpParams {
	Receive {
		manual: bool,
		outfile: Option<String>,
	},
	Finalize {
		fluff: bool,
		nopost: bool,
		outfile: Option<String>,
	},
	Post {
		fluff: bool,
	},
	Unpack,
	PayParse(PayParams),
}

impl SlateOpParams {
	pub fn name(&self) -> &'static str {
		match self {
			SlateOpParams::Receive { .. } => "receive",
			SlateOpParams::Finalize { .. } => "finalize",
			SlateOpParams::Post { .. } => "post",
			SlateOpParams::Unpack => "unpack",
			SlateOpParams::PayParse(_) => "pay",
		}
	}
}

/// Parameters for paying an invoice, carried through the confirm modal
#[derive(Clone)]
pub struct PayParams {
	pub dest_override: Option<String>,
	pub min_conf: u64,
	pub strategy_all: bool,
	pub ttl_blocks: Option<u64>,
	pub manual: bool,
	pub outfile: Option<String>,
}

pub fn spawn_slate_op<L, C, K>(ctx: &WorkerCtx<L, C, K>, input: SlateInput, op: SlateOpParams)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let name = op.name();
	spawn_op(ctx, name, move |owner, mask, ctx| match op {
		SlateOpParams::Receive { manual, outfile } => {
			let (mut slate, ret_address) = parse_slate(owner, mask, &input)?;
			let km = mask.cloned();
			let account = ctx.shared.account.lock().clone();
			controller::foreign_single_use(
				owner.wallet_inst.clone(),
				ctx.config_path.clone(),
				km,
				|api| {
					slate = api.receive_tx(&slate, Some(&account), None)?;
					Ok(())
				},
			)?;
			let dest = match &ret_address {
				Some(a) => String::try_from(a).unwrap_or_default(),
				None => String::new(),
			};
			if !can_send_tor(&ctx.tor_config, manual, ctx.test_mode) {
				return slatepack_output(
					owner,
					mask,
					&slate,
					&dest,
					outfile,
					false,
					false,
					"Receive: Response Slatepack",
				);
			}

			match ret_address.as_ref() {
				Some(addr) => {
					match try_slatepack_sync_workflow(
						&slate,
						addr,
						Some(ctx.tor_config.clone()),
						None,
						true,
					) {
						Ok(s) => {
							// Keep local tx state in sync after Tor handoff (see command::receive)
							{
								let mut w_lock = owner.wallet_inst.lock();
								let w = w_lock.lc_provider()?.wallet_inst()?;
								let parent_key_id = w.parent_key_id();
								let _ = update_tx_slate_state(w, mask, &parent_key_id, &s);
							}
							Ok(OpResult::Info(format!(
								"Transaction received and sent back to {} for finalization.",
								dest
							)))
						}
						Err(_) => slatepack_output(
							owner,
							mask,
							&slate,
							&dest,
							outfile,
							false,
							false,
							"Receive: Response Slatepack",
						),
					}
				}
				None => slatepack_output(
					owner,
					mask,
					&slate,
					&dest,
					outfile,
					false,
					false,
					"Receive: Response Slatepack",
				),
			}
		}
		SlateOpParams::Finalize {
			fluff,
			nopost,
			outfile,
		} => {
			let (mut slate, _) = parse_slate(owner, mask, &input)?;
			// Determine the finalization kind from the slate state,
			// like command::finalize does
			let is_invoice = slate.state == SlateState::Invoice2;
			if is_invoice {
				let km = mask.cloned();
				controller::foreign_single_use(
					owner.wallet_inst.clone(),
					ctx.config_path.clone(),
					km,
					|api| {
						slate = api.finalize_tx(&slate, false)?;
						Ok(())
					},
				)?;
			} else {
				slate = owner.finalize_tx(mask, &slate)?;
			}
			if !nopost {
				owner.post_tx(mask, &slate, fluff)?;
			}
			slatepack_output(
				owner,
				mask,
				&slate,
				"",
				outfile,
				false,
				true,
				"Finalize: Complete",
			)
		}
		SlateOpParams::Post { fluff } => {
			let (slate, _) = parse_slate(owner, mask, &input)?;
			owner.post_tx(mask, &slate, fluff)?;
			Ok(OpResult::Info("Posted transaction.".to_string()))
		}
		SlateOpParams::Unpack => {
			let mut body = String::new();
			let slatepack = match &input {
				SlateInput::File(f) => {
					let packer = Slatepacker::new(SlatepackerArgs {
						sender: None,
						recipients: vec![],
						dec_key: None,
					});
					PathToSlatepack::new(f.clone().into(), &packer, true).get_slatepack(false)?
				}
				SlateInput::Message(m) => {
					owner.decode_slatepack_message(mask, m.clone(), vec![])?
				}
			};
			body.push_str("SLATEPACK CONTENTS\n------------------\n");
			body.push_str(&format!("{}\n", slatepack));

			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: None,
			});
			let mut slatepack = slatepack;
			if slatepack.mode == 1 {
				let dec_key = owner.get_slatepack_secret_key(mask, 0)?;
				match slatepack.try_decrypt_payload(Some(&dec_key)) {
					Ok(_) => {
						body.push_str("\nSlatepack is encrypted for this wallet\n");
						body.push_str("\nDECRYPTED SLATEPACK\n-------------------\n");
						body.push_str(&format!("{}\n", slatepack));
						let slate = packer.get_slate(&slatepack)?;
						body.push_str("\nDECRYPTED SLATE\n---------------\n");
						body.push_str(&format!("{}\n", slate));
					}
					Err(_) => {
						body.push_str("\nSlatepack payload cannot be decrypted by this wallet\n");
					}
				}
			} else {
				let slate = packer.get_slate(&slatepack)?;
				body.push_str("\nSlatepack is not encrypted\n");
				body.push_str("\nSLATE\n-----\n");
				body.push_str(&format!("{}\n", slate));
			}
			Ok(OpResult::Text {
				title: "Slatepack Contents".to_string(),
				body,
				copy: None,
			})
		}
		SlateOpParams::PayParse(params) => {
			let (slate, ret_address) = parse_slate(owner, mask, &input)?;
			let dest = match &params.dest_override {
				Some(d) => d.clone(),
				None => match ret_address {
					Some(a) => String::try_from(&a).unwrap_or_default(),
					None => String::new(),
				},
			};
			Ok(OpResult::ConfirmPay {
				amount: amount_to_hr_string(slate.amount, false),
				dest,
				params,
				slate: Box::new(slate),
			})
		}
	});
}

/// Second phase of paying an invoice, run after the user confirms
pub fn spawn_pay_process<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	slate: Box<Slate>,
	dest: String,
	p: PayParams,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "pay", move |owner, mask, ctx| {
		let init_args = InitTxArgs {
			src_acct_name: None,
			amount: 0,
			minimum_confirmations: p.min_conf,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: p.strategy_all,
			ttl_blocks: p.ttl_blocks,
			send_args: None,
			..Default::default()
		};
		let slate = owner.process_invoice_tx(mask, &slate, init_args)?;
		if !can_send_tor(&ctx.tor_config, p.manual, ctx.test_mode) {
			return slatepack_output(
				owner,
				mask,
				&slate,
				&dest,
				p.outfile,
				true,
				false,
				"Pay: Response Slatepack",
			);
		}

		let dest_addr = match dest.as_str() {
			"" => None,
			s => SlatepackAddress::try_from(s).ok(),
		};
		match dest_addr.as_ref().and_then(|addr| {
			try_slatepack_sync_workflow(&slate, addr, Some(ctx.tor_config.clone()), None, true).ok()
		}) {
			Some(s) => {
				{
					let mut w_lock = owner.wallet_inst.lock();
					let w = w_lock.lc_provider()?.wallet_inst()?;
					let parent_key_id = w.parent_key_id();
					let _ = update_tx_slate_state(w, mask, &parent_key_id, &s);
				}
				Ok(OpResult::Info(format!(
					"Invoice paid and sent back to {} for finalization.",
					dest
				)))
			}
			None => slatepack_output(
				owner,
				mask,
				&slate,
				&dest,
				p.outfile,
				true,
				false,
				"Pay: Response Slatepack",
			),
		}
	});
}

pub fn spawn_invoice<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	amount: String,
	dest: String,
	outfile: Option<String>,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "invoice", move |owner, mask, _ctx| {
		let amount = amount_from_hr_string(amount.trim())
			.map_err(|e| Error::ArgumentError(format!("invalid amount: {}", e)))?;
		let issue_args = IssueInvoiceTxArgs {
			dest_acct_name: None,
			amount,
			target_slate_version: None,
		};
		let slate = owner.issue_invoice_tx(mask, issue_args)?;
		slatepack_output(
			owner,
			mask,
			&slate,
			&dest,
			outfile,
			false,
			false,
			"Invoice: Slatepack Created",
		)
	});
}

pub fn spawn_repost<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	id: u32,
	dump_file: Option<String>,
	fluff: bool,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "repost", move |owner, mask, _ctx| {
		let stored_tx_slate = match owner.get_stored_tx(mask, Some(id), None)? {
			None => {
				return Ok(OpResult::Error(format!(
					"Transaction with id {} does not have transaction data. Not reposting.",
					id
				)))
			}
			Some(s) => s,
		};
		let (_, txs) = owner.retrieve_txs(mask, true, Some(id), None, None)?;
		match dump_file {
			None => {
				if txs[0].confirmed {
					return Ok(OpResult::Error(format!(
						"Transaction with id {} is already confirmed. Not reposting.",
						id
					)));
				}
				if sig_is_blank(&stored_tx_slate.tx.as_ref().unwrap().kernels()[0].excess_sig) {
					return Ok(OpResult::Error(format!(
						"Transaction with id {} has not been finalized.",
						id
					)));
				}
				owner.post_tx(mask, &stored_tx_slate, fluff)?;
				Ok(OpResult::Info(format!("Reposted transaction {}.", id)))
			}
			Some(f) => {
				let mut tx_file = File::create(&f).map_err(io_err)?;
				let tx = stored_tx_slate.tx.ok_or_else(|| {
					Error::GenericError("Stored transaction is missing".to_string())
				})?;
				tx_file
					.write_all(json::to_string(&tx).unwrap().as_bytes())
					.map_err(io_err)?;
				tx_file.sync_all().map_err(io_err)?;
				Ok(OpResult::Info(format!(
					"Dumped transaction data for tx {} to {}.",
					id, f
				)))
			}
		}
	});
}

pub fn spawn_cancel<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "cancel", move |owner, mask, _ctx| {
		owner.cancel_tx(mask, tx_id, tx_slate_id)?;
		Ok(OpResult::Info("Transaction cancelled.".to_string()))
	});
}

pub fn spawn_account_create<L, C, K>(ctx: &WorkerCtx<L, C, K>, label: String)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "account", move |owner, mask, _ctx| {
		owner.create_account_path(mask, &label)?;
		Ok(OpResult::Info(format!("Account '{}' created.", label)))
	});
}

pub fn spawn_address<L, C, K>(ctx: &WorkerCtx<L, C, K>)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "address", move |owner, mask, ctx| {
		let address = owner.get_slatepack_address(mask, 0)?;
		let account = ctx.shared.account.lock().clone();
		Ok(OpResult::Text {
			title: "Slatepack Address".to_string(),
			body: format!("Address for account '{}':\n\n{}", account, address),
			copy: Some(address.to_string()),
		})
	});
}

pub fn spawn_rewind_hash<L, C, K>(ctx: &WorkerCtx<L, C, K>)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "rewind_hash", move |owner, mask, _ctx| {
		let rewind_hash = owner.get_rewind_hash(mask)?;
		Ok(OpResult::Text {
			title: "Wallet Rewind Hash".to_string(),
			body: rewind_hash.clone(),
			copy: Some(rewind_hash),
		})
	});
}

fn start_height_from(
	tip_height: u64,
	start_height: Option<u64>,
	backwards_from_tip: Option<u64>,
) -> u64 {
	match backwards_from_tip {
		Some(b) => tip_height.saturating_sub(b),
		None => start_height.unwrap_or(1),
	}
}

pub fn spawn_scan<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	start_height: Option<u64>,
	backwards_from_tip: Option<u64>,
	delete_unconfirmed: bool,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "scan", move |owner, mask, _ctx| {
		let tip_height = owner.node_height(mask)?.height;
		let start = start_height_from(tip_height, start_height, backwards_from_tip);
		log::warn!("Starting output scan from height {} ...", start);
		owner.scan(mask, Some(start), delete_unconfirmed)?;
		Ok(OpResult::Info("Wallet scan complete.".to_string()))
	});
}

pub fn spawn_scan_rewind_hash<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	rewind_hash: String,
	start_height: Option<u64>,
	backwards_from_tip: Option<u64>,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "scan_rewind_hash", move |owner, mask, _ctx| {
		let tip_height = owner.node_height(mask)?.height;
		let start = start_height_from(tip_height, start_height, backwards_from_tip);
		let result = owner.scan_rewind_hash(rewind_hash, Some(start))?;
		let mut body = format!(
			"Total balance: {}\nOutputs found: {}\n",
			amount_to_hr_string(result.total_balance, false),
			result.output_result.len()
		);
		if !result.output_result.is_empty() {
			body.push_str("\nCommitment / Value / Height / Confirmations\n");
			for o in &result.output_result {
				body.push_str(&format!(
					"{} / {} / {} / {}\n",
					o.commit,
					amount_to_hr_string(o.value, false),
					o.height,
					o.num_confirmations(tip_height),
				));
			}
		}
		Ok(OpResult::Text {
			title: "View Wallet Scan".to_string(),
			body,
			copy: None,
		})
	});
}

pub fn spawn_proof_export<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	output_file: String,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "export_proof", move |owner, mask, _ctx| {
		let proof = owner.retrieve_payment_proof(mask, true, tx_id, tx_slate_id)?;
		let mut proof_file = File::create(&output_file).map_err(io_err)?;
		proof_file
			.write_all(json::to_string_pretty(&proof).unwrap().as_bytes())
			.map_err(io_err)?;
		proof_file.sync_all().map_err(io_err)?;
		Ok(OpResult::Info(format!(
			"Payment proof exported to {}.",
			output_file
		)))
	});
}

pub fn spawn_proof_verify<L, C, K>(ctx: &WorkerCtx<L, C, K>, input_file: String)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	spawn_op(ctx, "verify_proof", move |owner, mask, _ctx| {
		let mut proof_f = File::open(&input_file).map_err(io_err)?;
		let mut proof = String::new();
		proof_f.read_to_string(&mut proof).map_err(io_err)?;
		let proof: PaymentProof = json::from_str(&proof)
			.map_err(|e| Error::GenericError(format!("Unable to parse payment proof: {}", e)))?;
		let (iam_sender, iam_recipient) = owner.verify_payment_proof(mask, &proof)?;
		let mut body = "Payment proof's signatures are valid.\n".to_string();
		if iam_sender {
			body.push_str("The proof's sender address belongs to this wallet.\n");
		}
		if iam_recipient {
			body.push_str("The proof's recipient address belongs to this wallet.\n");
		}
		if !iam_sender && !iam_recipient {
			body.push_str(
				"Neither the proof's sender nor recipient address belongs to this wallet.\n",
			);
		}
		Ok(OpResult::Text {
			title: "Payment Proof Verification".to_string(),
			body,
			copy: None,
		})
	});
}

/// Start the foreign (receive) listener on a background thread, mirroring
/// `command::listen` in cli mode. Uses the shared keychain mask so in-TUI
/// open/close is visible to the listener.
pub fn spawn_listener<L, C, K>(
	ctx: &WorkerCtx<L, C, K>,
	port: Option<u16>,
	no_tor: bool,
	bridge: Option<String>,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	if ctx.shared.listener_running.load(Ordering::Relaxed) {
		let _ = ctx.ui_tx.send(UiMsg::Op(OpResult::Error(
			"Listener is already running".to_string(),
		)));
		return;
	}
	let mut config = ctx.wallet_config.clone();
	if let Some(p) = port {
		config.api_listen_port = p;
	}
	let use_tor = if no_tor { Some(false) } else { None };
	let mask = ctx.shared.mask.clone();
	let addr = config.api_listen_addr();
	ctx.shared.listener_running.store(true, Ordering::Relaxed);
	let _ = ctx.ui_tx.send(UiMsg::Op(OpResult::Info(format!(
		"Listener starting on {} (runs until the wallet exits).",
		addr
	))));
	let ctx = ctx.clone();
	let shared = ctx.shared.clone();
	let ui_tx = ctx.ui_tx.clone();
	match thread::Builder::new()
		.name("wallet-tui-listener".to_string())
		.spawn(move || {
			let res = controller::foreign_listener(
				ctx.wallet_inst.clone(),
				ctx.config_path.clone(),
				bridge,
				use_tor,
				mask,
				&config.api_listen_addr(),
				ctx.tls_conf.clone(),
				ctx.test_mode,
			);
			ctx.shared.listener_running.store(false, Ordering::Relaxed);
			let msg = match res {
				Ok(_) => OpResult::Info("Listener stopped.".to_string()),
				Err(e) => OpResult::Error(format!("Listener failed: {}", e)),
			};
			let _ = ctx.ui_tx.send(UiMsg::Op(msg));
		}) {
		Ok(_) => {}
		Err(e) => {
			shared.listener_running.store(false, Ordering::Relaxed);
			let _ = ui_tx.send(UiMsg::Op(OpResult::Error(format!(
				"Failed to start listener: {}",
				e
			))));
		}
	}
}

/// Start the owner API listener on a background thread. Shares the same
/// keychain mask Arc as the TUI and forwards configured TLS settings.
pub fn spawn_owner_api<L, C, K>(ctx: &WorkerCtx<L, C, K>, port: Option<u16>, run_foreign: bool)
where
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	if ctx.shared.owner_api_running.load(Ordering::Relaxed) {
		let _ = ctx.ui_tx.send(UiMsg::Op(OpResult::Error(
			"Owner API is already running".to_string(),
		)));
		return;
	}
	let mut config = ctx.wallet_config.clone();
	if let Some(p) = port {
		config.owner_api_listen_port = Some(p);
	}
	if run_foreign {
		config.owner_api_include_foreign = Some(true);
	}
	let mask = ctx.shared.mask.clone();
	let addr = config.owner_api_listen_addr();
	ctx.shared.owner_api_running.store(true, Ordering::Relaxed);
	let _ = ctx.ui_tx.send(UiMsg::Op(OpResult::Info(format!(
		"Owner API starting on {} (runs until the wallet exits).",
		addr
	))));
	let ctx = ctx.clone();
	let shared = ctx.shared.clone();
	let ui_tx = ctx.ui_tx.clone();
	match thread::Builder::new()
		.name("wallet-tui-owner-api".to_string())
		.spawn(move || {
			// OwnerAPIHandler builds its own Owner from wallet + config path;
			// this instance only supplies those for owner_listener.
			let mut owner = Owner::new(
				ctx.wallet_inst.clone(),
				Some(ctx.status_tx.clone()),
				ctx.config_path.clone(),
			);
			let res = controller::owner_listener(
				&mut owner,
				mask,
				config.owner_api_listen_addr().as_str(),
				ctx.api_secret.clone(),
				ctx.tls_conf.clone(),
				config.owner_api_include_foreign,
				ctx.test_mode,
			);
			ctx.shared.owner_api_running.store(false, Ordering::Relaxed);
			let msg = match res {
				Ok(_) => OpResult::Info("Owner API stopped.".to_string()),
				Err(e) => OpResult::Error(format!("Owner API failed: {}", e)),
			};
			let _ = ctx.ui_tx.send(UiMsg::Op(msg));
		}) {
		Ok(_) => {}
		Err(e) => {
			shared.owner_api_running.store(false, Ordering::Relaxed);
			let _ = ui_tx.send(UiMsg::Op(OpResult::Error(format!(
				"Failed to start Owner API: {}",
				e
			))));
		}
	}
}

/// Run the dashboard refresher until the control channel closes. Reads are
/// local (`refresh_from_node: false`); node sync happens via the
/// `start_updater` thread the controller runs, so a slow or absent node
/// never stalls the UI.
pub fn spawn_refresher<L, C, K>(ctx: WorkerCtx<L, C, K>, ctrl_rx: mpsc::Receiver<RefreshCtrl>)
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let ui_tx = ctx.ui_tx.clone();
	match thread::Builder::new()
		.name("wallet-tui-refresher".to_string())
		.spawn(move || {
			let owner = Owner::new(
				ctx.wallet_inst.clone(),
				Some(ctx.status_tx.clone()),
				ctx.config_path.clone(),
			);
			let mut cached_address: Option<String> = None;
			loop {
				match ctrl_rx.recv_timeout(REFRESH_INTERVAL) {
					Ok(RefreshCtrl::Now) | Err(mpsc::RecvTimeoutError::Timeout) => {}
					Err(mpsc::RecvTimeoutError::Disconnected) => break,
				}
				if ctx.shared.is_locked() {
					cached_address = None;
					continue;
				}
				if ctx.shared.busy.lock().is_some() {
					continue;
				}
				let mask = ctx.shared.mask.lock().clone();
				let m = mask.as_ref();
				let min_conf = ctx.shared.min_conf.load(Ordering::Relaxed);
				let show_spent = ctx.shared.show_spent.load(Ordering::Relaxed);

				let mut view = WalletView {
					account: ctx.shared.account.lock().clone(),
					..Default::default()
				};
				match owner.retrieve_summary_info(m, false, min_conf) {
					Ok((validated, info)) => {
						// Match CLI: treat running updater as validated.
						view.validated =
							validated || ctx.shared.updater_running.load(Ordering::Relaxed);
						view.info = Some(info);
					}
					Err(e) => view.last_error = Some(e.to_string()),
				}
				if let Ok(accounts) = owner.accounts(m) {
					view.accounts = accounts;
				}
				if let Ok((_, outputs)) = owner.retrieve_outputs(m, show_spent, false, None) {
					view.outputs = outputs;
				}
				if let Ok((_, txs)) = owner.retrieve_txs(m, false, None, None, None) {
					view.txs = txs;
				}
				if let Ok(h) = owner.node_height(m) {
					view.node_height = Some(h.height);
				}
				if cached_address.is_none() {
					if let Ok(a) = owner.get_slatepack_address(m, 0) {
						cached_address = Some(a.to_string());
					}
				}
				view.address = cached_address.clone();

				if ctx.ui_tx.send(UiMsg::View(Box::new(view))).is_err() {
					break;
				}
			}
		}) {
		Ok(_) => {}
		Err(e) => {
			let _ = ui_tx.send(UiMsg::Op(OpResult::Error(format!(
				"Failed to start dashboard refresher: {}",
				e
			))));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::can_send_tor;
	use grin_wallet_config::TorConfig;

	#[test]
	fn can_send_tor_manual_skips() {
		let mut tor = TorConfig::default();
		tor.skip_send_attempt = Some(false);
		assert!(!can_send_tor(&tor, true, false));
		assert!(can_send_tor(&tor, false, false));
	}

	#[test]
	fn can_send_tor_respects_config_when_not_manual() {
		let mut tor = TorConfig::default();
		tor.skip_send_attempt = Some(true);
		// Manual=false must not override config with Some(false).
		assert!(!can_send_tor(&tor, false, false));
		assert!(!can_send_tor(&tor, true, false));
	}

	#[test]
	fn can_send_tor_test_mode_never() {
		let tor = TorConfig::default();
		assert!(!can_send_tor(&tor, false, true));
	}
}
