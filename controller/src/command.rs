// Copyright 2021 The Grin Developers
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

//! Grin wallet command-line function implementations

use crate::api::TLSConfig;
use crate::apiwallet::{try_slatepack_sync_workflow, Owner};
use crate::config::{TorConfig, WalletConfig, WALLET_CONFIG_FILE_NAME};
use crate::core::{core, global};
use crate::error::Error;
use crate::impls::PathToSlatepack;
use crate::impls::SlateGetter as _;
use crate::keychain;
use crate::libwallet::api_impl::types::update_tx_slate_state;
use crate::libwallet::{
	self, InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, Slate, SlateState,
	SlatepackAddress, Slatepacker, SlatepackerArgs, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ZeroingString};
use crate::{controller, display};

use qr_code::QrCode;
use serde_json as json;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

fn show_recovery_phrase(phrase: ZeroingString) {
	println!("Your recovery phrase is:");
	println!();
	println!("{}", &*phrase);
	println!();
	println!("Please back-up these words in a non-digital format.");
}

/// Arguments common to all wallet commands
#[derive(Clone)]
pub struct GlobalArgs {
	pub account: String,
	pub api_secret: Option<String>,
	pub node_api_secret: Option<String>,
	pub show_spent: bool,
	pub password: Option<ZeroingString>,
	pub tls_conf: Option<TLSConfig>,
}

/// Arguments for init command
pub struct InitArgs {
	/// BIP39 recovery phrase length
	pub list_length: usize,
	pub password: ZeroingString,
	pub config: WalletConfig,
	pub recovery_phrase: Option<ZeroingString>,
	pub restore: bool,
}

/// Write config (default if None), initiate the wallet
pub fn init<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	_g_args: &GlobalArgs,
	args: InitArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// Assume global chain type has already been initialized.
	let chain_type = global::get_chain_type();

	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	p.create_config(&chain_type, WALLET_CONFIG_FILE_NAME, None, None, None)?;
	p.create_wallet(
		None,
		args.recovery_phrase,
		args.list_length,
		args.password.clone(),
		test_mode,
	)?;

	let m = p.get_mnemonic(None, args.password)?;
	show_recovery_phrase(m);
	Ok(())
}

/// Argument for recover
pub struct RecoverArgs {
	pub passphrase: ZeroingString,
}

pub fn recover<L, C, K>(owner_api: &mut Owner<L, C, K>, args: RecoverArgs) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	let m = p.get_mnemonic(None, args.passphrase)?;
	show_recovery_phrase(m);
	Ok(())
}

pub fn rewind_hash<'a, L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let rewind_hash = owner_api.get_rewind_hash(keychain_mask)?;
	println!();
	println!("Wallet Rewind Hash");
	println!("-------------------------------------");
	println!("{}", rewind_hash);
	println!();
	Ok(())
}

/// Arguments for rewind hash view wallet scan command
pub struct ViewWalletScanArgs {
	pub rewind_hash: String,
	pub start_height: Option<u64>,
	pub backwards_from_tip: Option<u64>,
}

pub fn scan_rewind_hash<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	args: ViewWalletScanArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let rewind_hash = args.rewind_hash;
	let tip_height = owner_api.node_height(None)?.height;
	let start_height = match args.backwards_from_tip {
		Some(b) => tip_height.saturating_sub(b),
		None => args.start_height.unwrap_or_else(|| 1),
	};
	warn!(
		"Starting view wallet output scan from height {} ...",
		start_height
	);
	let result = owner_api.scan_rewind_hash(rewind_hash, Some(start_height));
	let deci_sec = Duration::from_millis(100);
	thread::sleep(deci_sec);
	match result {
		Ok(res) => {
			warn!("View wallet check complete");
			if res.total_balance != 0 {
				display::view_wallet_output(res.clone(), tip_height, dark_scheme)?;
			}
			display::view_wallet_balance(res.clone(), tip_height, dark_scheme);
			Ok(())
		}
		Err(e) => {
			error!("View wallet check failed: {}", e);
			Err(Error::from(e))
		}
	}
}

pub fn listen<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	config: WalletConfig,
	bridge: Option<String>,
	use_tor: Option<bool>,
	g_args: &GlobalArgs,
	cli_mode: bool,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let wallet_inst = owner_api.wallet_inst.clone();
	let config_path = owner_api.config_path();
	let g_args = g_args.clone();
	let api_thread = thread::Builder::new()
		.name("wallet-http-listener".to_string())
		.spawn(move || {
			let res = controller::foreign_listener(
				wallet_inst,
				config_path,
				bridge,
				use_tor,
				keychain_mask,
				&config.api_listen_addr(),
				g_args.tls_conf.clone(),
				test_mode,
			);
			if let Err(e) = res {
				error!("Error starting listener: {}", e);
			}
		});
	if let Ok(t) = api_thread {
		if !cli_mode {
			let r = t.join();
			if let Err(_) = r {
				error!("Error starting listener");
				return Err(Error::ListenerError);
			}
		}
	}
	Ok(())
}

pub fn owner_api<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<SecretKey>,
	config: &WalletConfig,
	g_args: &GlobalArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// keychain mask needs to be a sinlge instance, in case the foreign API is
	// also being run at the same time
	let km = Arc::new(Mutex::new(keychain_mask));
	let res = controller::owner_listener(
		owner_api,
		km,
		config.owner_api_listen_addr().as_str(),
		g_args.api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign,
		test_mode,
	);
	if let Err(e) = res {
		return Err(Error::LibWallet(e));
	}
	Ok(())
}

/// Arguments for account command
pub struct AccountArgs {
	pub create: Option<String>,
}

pub fn account<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: AccountArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	if args.create.is_none() {
		let res = {
			let acct_mappings = owner_api.accounts(keychain_mask)?;
			// give logging thread a moment to catch up
			thread::sleep(Duration::from_millis(200));
			display::accounts(acct_mappings);
			Ok(())
		};
		if let Err(e) = res {
			error!("Error listing accounts: {}", e);
			return Err(Error::LibWallet(e));
		}
	} else {
		let label = args.create.unwrap();
		let res = {
			owner_api.create_account_path(keychain_mask, &label)?;
			thread::sleep(Duration::from_millis(200));
			info!("Account: '{}' Created!", label);
			Ok(())
		};
		if let Err(e) = res {
			thread::sleep(Duration::from_millis(200));
			error!("Error creating account '{}': {}", label, e);
			return Err(Error::LibWallet(e));
		}
	}
	Ok(())
}

/// Arguments for the send command
#[derive(Clone)]
pub struct SendArgs {
	pub amount: u64,
	pub amount_includes_fee: bool,
	pub use_max_amount: bool,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub late_lock: bool,
	pub dest: Option<String>,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
	pub payment_proof_address: Option<String>,
	pub ttl_blocks: Option<u64>,
	pub skip_tor: Option<bool>,
	pub outfile: Option<String>,
	pub bridge: Option<String>,
	pub slatepack_qr: bool,
}

pub fn send<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: SendArgs,
	mut tor_config: TorConfig,
	dark_scheme: bool,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let dest = if args.estimate_selection_strategies {
		None
	} else {
		args.dest
			.as_deref()
			.map(SlatepackAddress::try_from)
			.transpose()?
	};

	let mut slate = Slate::blank(2, false);
	let mut amount = args.amount;
	if args.use_max_amount {
		let (_, wallet_info) =
			owner_api.retrieve_summary_info(keychain_mask, true, args.minimum_confirmations)?;
		amount = wallet_info.amount_currently_spendable;
	}
	if args.estimate_selection_strategies {
		let strategies = vec!["smallest", "all"]
			.into_iter()
			.map(|strategy| {
				let init_args = InitTxArgs {
					src_acct_name: None,
					amount,
					amount_includes_fee: Some(args.amount_includes_fee),
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs as u32,
					num_change_outputs: args.change_outputs as u32,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					..Default::default()
				};
				let slate = owner_api.init_send_tx(keychain_mask, init_args)?;
				Ok((strategy, slate.amount, slate.fee_fields))
			})
			.collect::<Result<Vec<_>, grin_wallet_libwallet::Error>>()?;
		display::estimate(amount, strategies, dark_scheme);
	} else {
		let payment_proof_recipient_address = args
			.payment_proof_address
			.as_deref()
			.map(SlatepackAddress::try_from)
			.transpose()?;
		let init_args = InitTxArgs {
			src_acct_name: None,
			amount,
			amount_includes_fee: Some(args.amount_includes_fee),
			minimum_confirmations: args.minimum_confirmations,
			max_outputs: args.max_outputs as u32,
			num_change_outputs: args.change_outputs as u32,
			selection_strategy_is_use_all: args.selection_strategy == "all",
			target_slate_version: args.target_slate_version,
			payment_proof_recipient_address,
			ttl_blocks: args.ttl_blocks,
			send_args: None,
			late_lock: Some(args.late_lock),
			..Default::default()
		};
		let result = owner_api.init_send_tx(keychain_mask, init_args);
		slate = match result {
			Ok(s) => {
				info!(
					"Tx created: {} grin to {} (strategy '{}')",
					core::amount_to_hr_string(amount, false),
					dest.as_ref()
						.map(ToString::to_string)
						.unwrap_or_else(|| "no destination".to_string()),
					args.selection_strategy,
				);
				s
			}
			Err(e) => {
				info!("Tx not created: {}", e);
				return Err(Error::from(e));
			}
		};
	}

	if args.estimate_selection_strategies {
		return Ok(());
	}

	if let Some(b) = args.bridge.clone() {
		tor_config.bridge.bridge_line = Some(b);
	}

	let output_sp = || -> Result<(), Error> {
		Ok(output_slatepack(
			owner_api,
			keychain_mask,
			&slate,
			dest.clone(),
			args.outfile,
			true,
			false,
			args.slatepack_qr,
		)?)
	};

	let can_send = tor_config.send_tor(args.skip_tor);
	if test_mode || !can_send || dest.is_none() {
		return output_sp();
	}

	let dest = dest.as_ref().unwrap();
	let res = try_slatepack_sync_workflow(&slate, dest, Some(tor_config), None, false);

	match res {
		Ok(s) => {
			owner_api.tx_lock_outputs(keychain_mask, &s)?;
			let ret_slate = owner_api.finalize_tx(keychain_mask, &s)?;
			let result = owner_api.post_tx(keychain_mask, &ret_slate, args.fluff);
			match result {
				Ok(_) => {
					println!("Tx sent successfully",);
				}
				Err(e) => {
					error!("Tx sent fail: {}", e);
					return Err(e.into());
				}
			}
		}
		Err(e) => {
			error!("Error sending slate sync: {}", e);
			output_sp()?;
		}
	}
	Ok(())
}

pub fn output_slatepack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	dest: Option<SlatepackAddress>,
	out_file_override: Option<String>,
	lock: bool,
	finalizing: bool,
	show_qr: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// Output the slatepack file to stdout and to a file
	// encrypt for recipient by default
	let recipients = match dest.clone() {
		Some(a) => vec![a],
		None => vec![],
	};
	let message = owner_api.create_slatepack_message(keychain_mask, &slate, Some(0), recipients)?;
	let tld = owner_api.get_top_level_directory()?;

	// create a directory to which files will be output
	let slate_dir = format!("{}/{}", tld, "slatepack");
	let _ = std::fs::create_dir_all(slate_dir.clone());
	let out_file_name = match out_file_override {
		None => format!("{}/{}.{}.slatepack", slate_dir, slate.id, slate.state),
		Some(f) => f,
	};

	if lock {
		owner_api.tx_lock_outputs(keychain_mask, &slate)?;
	}

	println!("{}", out_file_name);
	let mut output = File::create(out_file_name.clone())?;
	output.write_all(&message.as_bytes())?;
	output.sync_all()?;

	println!();
	if !finalizing {
		println!("Slatepack data follows. Please provide this output to the other party");
	} else {
		println!("Slatepack data follows.");
	}
	println!();
	println!("--- CUT BELOW THIS LINE ---");
	println!();
	println!("{}", message);
	println!("--- CUT ABOVE THIS LINE ---");
	println!();
	println!("Slatepack data was also output to");
	println!();
	println!("{}", out_file_name);
	println!();
	if show_qr {
		if let Ok(qr_string) = QrCode::new(message) {
			println!("{}", qr_string.to_string(false, 3));
			println!();
		}
	}
	if dest.is_some() {
		println!("The slatepack data is encrypted for the recipient only");
	} else {
		println!("The slatepack data is NOT encrypted");
	}
	println!();
	Ok(())
}

// Parse a slate and slatepack from a message
pub fn parse_slatepack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	filename: Option<String>,
	message: Option<String>,
) -> Result<(Slate, Option<SlatepackAddress>), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut ret_address = None;
	let slate = match filename {
		Some(f) => {
			// otherwise, get slate from slatepack
			let dec_key = owner_api.get_slatepack_secret_key(keychain_mask, 0)?;
			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: Some(&dec_key),
			});
			let pts = PathToSlatepack::new(f.into(), &packer, true);
			let sl = Some(pts.get_tx()?.0);
			ret_address = pts.get_slatepack(true)?.sender;
			sl
		}
		None => None,
	};

	let slate = match slate {
		Some(s) => s,
		None => {
			// try and parse directly from input_slatepack_message
			match message {
				Some(message) => {
					let slate = owner_api.slate_from_slatepack_message(
						keychain_mask,
						message.clone(),
						vec![0],
					)?;
					let slatepack = owner_api.decode_slatepack_message(
						keychain_mask,
						message.clone(),
						vec![0],
					)?;
					ret_address = slatepack.sender;
					slate
				}
				None => {
					let msg = "No slate provided via file or direct input";
					return Err(Error::GenericError(msg.into()).into());
				}
			}
		}
	};
	Ok((slate, ret_address))
}

/// Receive command argument
#[derive(Clone)]
pub struct ReceiveArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub skip_tor: Option<bool>,
	pub outfile: Option<String>,
	pub bridge: Option<String>,
	pub slatepack_qr: bool,
}

pub fn receive<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
	mut tor_config: TorConfig,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (mut slate, ret_address) = parse_slatepack(
		owner_api,
		keychain_mask,
		args.input_file,
		args.input_slatepack_message,
	)?;

	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};

	if let Some(b) = args.bridge {
		tor_config.bridge.bridge_line = Some(b);
	}

	controller::foreign_single_use(
		owner_api.wallet_inst.clone(),
		owner_api.config_path(),
		km,
		|api| {
			slate = api.receive_tx(&slate, Some(&g_args.account), None)?;
			Ok(())
		},
	)?;

	let output_sp = || -> Result<(), Error> {
		Ok(output_slatepack(
			owner_api,
			keychain_mask,
			&slate,
			ret_address.clone(),
			args.outfile,
			false,
			false,
			args.slatepack_qr,
		)?)
	};

	let can_send = tor_config.send_tor(args.skip_tor);
	if test_mode || !can_send || ret_address.is_none() {
		return output_sp();
	}

	let dest = ret_address.as_ref().unwrap();
	let res = try_slatepack_sync_workflow(&slate, dest, Some(tor_config), None, true);

	match res {
		Ok(s) => {
			// Update slate state.
			{
				let mut w_lock = owner_api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let parent_key_id = w.parent_key_id();
				match update_tx_slate_state(w, keychain_mask, &parent_key_id, &s) {
					Ok(_) => {}
					Err(e) => error!("Error on updating slate state: {}", e),
				}
			}
			println!();
			println!(
				"Transaction received and sent back to sender at {} for finalization.",
				dest
			);
			println!();
		}
		Err(e) => {
			error!("Error sending slate sync: {}", e);
			output_sp()?;
		}
	}
	Ok(())
}

pub fn unpack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ReceiveArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slatepack = match args.input_file {
		Some(f) => {
			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: None,
			});
			PathToSlatepack::new(f.into(), &packer, true).get_slatepack(false)?
		}
		None => match args.input_slatepack_message {
			Some(mes) => owner_api.decode_slatepack_message(keychain_mask, mes, vec![])?,
			None => {
				return Err(Error::ArgumentError("Invalid Slatepack Input".into()).into());
			}
		},
	};
	println!();
	println!("SLATEPACK CONTENTS");
	println!("------------------");
	println!("{}", slatepack);
	println!("------------------");

	let packer = Slatepacker::new(SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key: None,
	});

	if slatepack.mode == 1 {
		let dec_key = owner_api.get_slatepack_secret_key(keychain_mask, 0)?;
		match slatepack.try_decrypt_payload(Some(&dec_key)) {
			Ok(_) => {
				println!("Slatepack is encrypted for this wallet");
				println!();
				println!("DECRYPTED SLATEPACK");
				println!("-------------------");
				println!("{}", slatepack);
				let slate = packer.get_slate(&slatepack)?;
				println!();
				println!("DECRYPTED SLATE");
				println!("---------------");
				println!("{}", slate);
			}
			Err(_) => {
				println!("Slatepack payload cannot be decrypted by this wallet");
			}
		}
	} else {
		let slate = packer.get_slate(&slatepack)?;
		println!("Slatepack is not encrypted");
		println!();
		println!("SLATE");
		println!("-----");
		println!("{}", slate);
	}
	Ok(())
}

/// Finalize command args
#[derive(Clone)]
pub struct FinalizeArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub fluff: bool,
	pub nopost: bool,
	pub outfile: Option<String>,
	pub slatepack_qr: bool,
}

pub fn finalize<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: FinalizeArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (mut slate, _ret_address) = parse_slatepack(
		owner_api,
		keychain_mask,
		args.input_file.clone(),
		args.input_slatepack_message.clone(),
	)?;

	// Rather than duplicating the entire command, we'll just
	// try to determine what kind of finalization this is
	// based on the slate state
	let is_invoice = slate.state == SlateState::Invoice2;

	if is_invoice {
		let km = match keychain_mask.as_ref() {
			None => None,
			Some(&m) => Some(m.to_owned()),
		};
		controller::foreign_single_use(
			owner_api.wallet_inst.clone(),
			owner_api.config_path(),
			km,
			|api| {
				slate = api.finalize_tx(&slate, false)?;
				Ok(())
			},
		)?;
	} else {
		slate = owner_api.finalize_tx(keychain_mask, &slate)?
	}

	if !&args.nopost {
		let result = owner_api.post_tx(keychain_mask, &slate, args.fluff);
		match result {
			Ok(_) => {
				info!("Transaction sent successfully, check the wallet again for confirmation.");
				println!("Transaction posted");
			}
			Err(e) => {
				error!("Tx not sent: {}", e);
				return Err(Error::from(e));
			}
		}
	}

	println!("Transaction finalized successfully");

	output_slatepack(
		owner_api,
		keychain_mask,
		&slate,
		None,
		args.outfile,
		false,
		true,
		args.slatepack_qr,
	)?;

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// Slatepack address
	pub dest: Option<String>,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
	/// output file override
	pub outfile: Option<String>,
	/// show slatepack as QR code
	pub slatepack_qr: bool,
}

pub fn issue_invoice_tx<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let dest = args
		.dest
		.as_deref()
		.map(SlatepackAddress::try_from)
		.transpose()?;
	let issue_args = args.issue_args.clone();

	let slate = owner_api.issue_invoice_tx(keychain_mask, issue_args)?;

	output_slatepack(
		owner_api,
		keychain_mask,
		&slate,
		dest,
		args.outfile,
		false,
		false,
		args.slatepack_qr,
	)?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub ret_address: Option<String>,
	pub max_outputs: usize,
	pub slate: Slate,
	pub estimate_selection_strategies: bool,
	pub ttl_blocks: Option<u64>,
	pub skip_tor: Option<bool>,
	pub outfile: Option<String>,
	pub bridge: Option<String>,
	pub slatepack_qr: bool,
}

/// Process invoice
pub fn process_invoice<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	mut tor_config: TorConfig,
	args: ProcessInvoiceArgs,
	dark_scheme: bool,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let ret_address = args
		.ret_address
		.as_deref()
		.map(SlatepackAddress::try_from)
		.transpose()?;
	let mut slate = args.slate.clone();

	if args.estimate_selection_strategies {
		let strategies = vec!["smallest", "all"]
			.into_iter()
			.map(|strategy| {
				let init_args = InitTxArgs {
					src_acct_name: None,
					amount: slate.amount,
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs as u32,
					num_change_outputs: 1u32,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					..Default::default()
				};
				let slate = owner_api.init_send_tx(keychain_mask, init_args).unwrap();
				(strategy, slate.amount, slate.fee_fields)
			})
			.collect();
		display::estimate(slate.amount, strategies, dark_scheme);
	} else {
		let init_args = InitTxArgs {
			src_acct_name: None,
			amount: 0,
			minimum_confirmations: args.minimum_confirmations,
			max_outputs: args.max_outputs as u32,
			num_change_outputs: 1u32,
			selection_strategy_is_use_all: args.selection_strategy == "all",
			ttl_blocks: args.ttl_blocks,
			send_args: None,
			..Default::default()
		};
		let result = owner_api.process_invoice_tx(keychain_mask, &slate, init_args);
		slate = match result {
			Ok(s) => {
				info!(
					"Invoice processed: {} grin (strategy '{}')",
					core::amount_to_hr_string(slate.amount, false),
					args.selection_strategy,
				);
				s
			}
			Err(e) => {
				info!("Tx not created: {}", e);
				return Err(Error::from(e));
			}
		};
	}

	if let Some(b) = args.bridge {
		tor_config.bridge.bridge_line = Some(b);
	}

	let output_sp = || -> Result<(), Error> {
		Ok(output_slatepack(
			owner_api,
			keychain_mask,
			&slate,
			ret_address.clone(),
			args.outfile,
			true,
			false,
			args.slatepack_qr,
		)?)
	};

	let can_send = tor_config.send_tor(args.skip_tor);
	if test_mode || !can_send || ret_address.is_none() {
		return output_sp();
	}

	let dest = ret_address.as_ref().unwrap();
	let res = try_slatepack_sync_workflow(&slate, dest, Some(tor_config), None, true);

	match res {
		Ok(s) => {
			// Update slate state.
			{
				let mut w_lock = owner_api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let parent_key_id = w.parent_key_id();
				match update_tx_slate_state(w, keychain_mask, &parent_key_id, &s) {
					Ok(_) => {}
					Err(e) => error!("Error on updating slate state: {}", e),
				}
			}
			println!();
			println!(
				"Transaction paid and sent back to initiator at {} for finalization.",
				dest
			);
			println!();
		}
		Err(e) => {
			error!("Error sending slate sync: {}", e);
			output_sp()?;
		}
	}
	Ok(())
}

/// Info command args
pub struct InfoArgs {
	pub minimum_confirmations: u64,
}

pub fn info<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: InfoArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	let (validated, wallet_info) =
		owner_api.retrieve_summary_info(keychain_mask, true, args.minimum_confirmations)?;
	display::info(
		&g_args.account,
		&wallet_info,
		validated || updater_running,
		dark_scheme,
	);
	Ok(())
}

pub fn outputs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	let res = owner_api.node_height(keychain_mask)?;
	let (validated, outputs) =
		owner_api.retrieve_outputs(keychain_mask, g_args.show_spent, true, None)?;
	display::outputs(
		&g_args.account,
		res.height,
		validated || updater_running,
		outputs,
		dark_scheme,
	)?;
	Ok(())
}

/// Txs command args
pub struct TxsArgs {
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub count: Option<u32>,
}

pub fn txs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: TxsArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	let res = owner_api.node_height(keychain_mask)?;
	// Note advanced query args not currently supported by command line client
	let (validated, txs) =
		owner_api.retrieve_txs(keychain_mask, true, args.id, args.tx_slate_id, None)?;
	let include_status = !args.id.is_some() && !args.tx_slate_id.is_some();
	// If view count is specified, restrict the TX list to `txs.len() - count`
	let first_tx = args
		.count
		.map_or(0, |c| txs.len().saturating_sub(c as usize));
	display::txs(
		&g_args.account,
		res.height,
		validated || updater_running,
		&txs[first_tx..],
		include_status,
		dark_scheme,
	)?;

	// if given a particular transaction id or uuid, also get and display associated
	// inputs/outputs and messages
	let id = if args.id.is_some() {
		args.id
	} else if args.tx_slate_id.is_some() {
		if let Some(tx) = txs.iter().find(|t| t.tx_slate_id == args.tx_slate_id) {
			Some(tx.id)
		} else {
			println!("Could not find a transaction matching given txid.\n");
			None
		}
	} else {
		None
	};

	if id.is_some() {
		let (_, outputs) = owner_api.retrieve_outputs(keychain_mask, true, false, id)?;
		display::outputs(
			&g_args.account,
			res.height,
			validated || updater_running,
			outputs,
			dark_scheme,
		)?;
		// should only be one here, but just in case
		for tx in txs {
			display::payment_proof(&tx)?;
		}
	}
	Ok(())
}

/// Post
#[derive(Clone)]
pub struct PostArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub fluff: bool,
}

pub fn post<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: PostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (slate, _ret_address) = parse_slatepack(
		owner_api,
		keychain_mask,
		args.input_file,
		args.input_slatepack_message,
	)?;

	let fluff = args.fluff;
	owner_api.post_tx(keychain_mask, &slate, fluff)?;
	info!("Posted transaction");
	Ok(())
}

/// Repost
pub struct RepostArgs {
	pub id: u32,
	pub dump_file: Option<String>,
	pub fluff: bool,
}

pub fn repost<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: RepostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let stored_tx_slate = match owner_api.get_stored_tx(keychain_mask, Some(args.id), None)? {
		None => {
			error!(
				"Transaction with id {} does not have transaction data. Not reposting.",
				args.id
			);
			return Ok(());
		}
		Some(s) => s,
	};
	let (_, txs) = owner_api.retrieve_txs(keychain_mask, true, Some(args.id), None, None)?;
	match args.dump_file {
		None => {
			if txs[0].confirmed {
				error!(
					"Transaction with id {} is confirmed. Not reposting.",
					args.id
				);
				return Ok(());
			}
			if libwallet::sig_is_blank(
				&stored_tx_slate.tx.as_ref().unwrap().kernels()[0].excess_sig,
			) {
				error!("Transaction at {} has not been finalized.", args.id);
				return Ok(());
			}

			match owner_api.post_tx(keychain_mask, &stored_tx_slate, args.fluff) {
				Ok(_) => info!("Reposted transaction at {}", args.id),
				Err(e) => error!("Could not repost transaction at {}. Reason: {}", args.id, e),
			}
			return Ok(());
		}
		Some(f) => {
			let mut tx_file =
				File::create(f.clone()).map_err(|e| Error::GenericError(format!("{}", e)))?;
			tx_file
				.write_all(
					json::to_string(&stored_tx_slate.tx.unwrap())
						.unwrap()
						.as_bytes(),
				)
				.map_err(|e| Error::GenericError(format!("{}", e)))?;
			tx_file
				.sync_all()
				.map_err(|e| Error::GenericError(format!("{}", e)))?;
			info!("Dumped transaction data for tx {} to {}", args.id, f);
		}
	}
	Ok(())
}

/// Cancel
pub struct CancelArgs {
	pub tx_id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub tx_id_string: String,
}

pub fn cancel<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CancelArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let result = owner_api.cancel_tx(keychain_mask, args.tx_id, args.tx_slate_id);
	match result {
		Ok(_) => {
			info!("Transaction {} Cancelled", args.tx_id_string);
			Ok(())
		}
		Err(e) => {
			error!("TX Cancellation failed: {}", e);
			Err(Error::from(e))
		}
	}
}

/// wallet check
pub struct CheckArgs {
	pub delete_unconfirmed: bool,
	pub start_height: Option<u64>,
	pub backwards_from_tip: Option<u64>,
}

pub fn scan<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CheckArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let tip_height = owner_api.node_height(keychain_mask)?.height;
	let start_height = match args.backwards_from_tip {
		Some(b) => tip_height.saturating_sub(b),
		None => args.start_height.unwrap_or_else(|| 1),
	};
	warn!("Starting output scan from height {} ...", start_height);
	let result = owner_api.scan(keychain_mask, Some(start_height), args.delete_unconfirmed);
	match result {
		Ok(_) => {
			warn!("Wallet check complete",);
			Ok(())
		}
		Err(e) => {
			error!("Wallet check failed: {}", e);
			Err(Error::from(e))
		}
	}
}

/// Payment Proof Address
pub fn address<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	g_args: &GlobalArgs,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// Just address at derivation index 0 for now
	let address = owner_api.get_slatepack_address(keychain_mask, 0)?;
	println!();
	println!("Address for account - {}", g_args.account);
	println!("-------------------------------------");
	println!("{}", address);
	println!();
	Ok(())
}

/// Proof Export Args
pub struct ProofExportArgs {
	pub output_file: String,
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
}

pub fn proof_export<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofExportArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let result = owner_api.retrieve_payment_proof(keychain_mask, true, args.id, args.tx_slate_id);
	match result {
		Ok(p) => {
			// actually export proof
			let mut proof_file = File::create(args.output_file.clone())
				.map_err(|e| Error::GenericError(format!("{}", e)))?;
			proof_file
				.write_all(json::to_string_pretty(&p).unwrap().as_bytes())
				.map_err(|e| Error::GenericError(format!("{}", e)))?;
			proof_file
				.sync_all()
				.map_err(|e| Error::GenericError(format!("{}", e)))?;
			warn!("Payment proof exported to {}", args.output_file);
			Ok(())
		}
		Err(e) => {
			error!("Proof export failed: {}", e);
			Err(Error::from(e))
		}
	}
}

/// Proof Verify Args
pub struct ProofVerifyArgs {
	pub input_file: String,
}

pub fn proof_verify<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofVerifyArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut proof_f = match File::open(&args.input_file) {
		Ok(p) => p,
		Err(e) => {
			let msg = format!("{}", e);
			error!(
				"Unable to open payment proof file at {}: {}",
				args.input_file, e
			);
			return Err(Error::from(libwallet::Error::PaymentProofParsing(msg)));
		}
	};
	let mut proof = String::new();
	proof_f
		.read_to_string(&mut proof)
		.map_err(|e| Error::GenericError(format!("{}", e)))?;
	// read
	let proof: PaymentProof = match json::from_str(&proof) {
		Ok(p) => p,
		Err(e) => {
			let msg = format!("{}", e);
			error!("Unable to parse payment proof file: {}", e);
			return Err(Error::from(libwallet::Error::PaymentProofParsing(msg)));
		}
	};
	let result = owner_api.verify_payment_proof(keychain_mask, &proof);
	match result {
		Ok((iam_sender, iam_recipient)) => {
			println!("Payment proof's signatures are valid.");
			if iam_sender {
				println!("The proof's sender address belongs to this wallet.");
			}
			if iam_recipient {
				println!("The proof's recipient address belongs to this wallet.");
			}
			if !iam_recipient && !iam_sender {
				println!(
					"Neither the proof's sender nor recipient address belongs to this wallet."
				);
			}
			Ok(())
		}
		Err(e) => {
			error!("Proof not valid: {}", e);
			Err(Error::from(e))
		}
	}
}
