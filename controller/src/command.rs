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
use crate::keychain;
use crate::libwallet::api_impl::types::update_tx_slate_state;
use crate::libwallet::contract::can_finalize;
use crate::libwallet::contract::types::{
	ContractNewArgsAPI, ContractRevokeArgsAPI, ContractSetupArgsAPI, OutputSelectionArgs,
	PaymentMemo, ProofArgs, ProofType,
};
use crate::libwallet::{
	self, InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, Slate, SlateState,
	SlatepackAddress, Slatepacker, SlatepackerArgs, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ZeroingString};
use crate::{controller, display};

use qr_code::QrCode;
use serde::{Deserialize, Serialize};
use serde_json as json;
use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::io;
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

fn max_retry_args(mut init_args: InitTxArgs, amount: u64, max_inputs: u32) -> InitTxArgs {
	init_args.amount = amount;
	init_args.max_outputs = max_inputs;
	init_args.selection_strategy_is_use_all = true;
	init_args
}

fn estimate_strategies(use_max_amount: bool) -> &'static [&'static str] {
	if use_max_amount {
		&["all"]
	} else {
		&["smallest", "all"]
	}
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
	let (info_updated, update_skipped, wallet_info) = owner_api
		.retrieve_summary_info_with_refresh_status(
			keychain_mask,
			true,
			args.minimum_confirmations,
		)?;
	if args.use_max_amount {
		amount = wallet_info.amount_currently_spendable;
	}
	if !info_updated && !update_skipped {
		warn!("Wallet info update failed: node connection error");
	}
	if args.estimate_selection_strategies {
		let strategies = estimate_strategies(args.use_max_amount)
			.iter()
			.copied()
			.map(|strategy| {
				let mut init_args = InitTxArgs {
					src_acct_name: None,
					amount,
					amount_includes_fee: Some(args.amount_includes_fee),
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs as u32,
					num_change_outputs: args.change_outputs as u32,
					selection_strategy_is_use_all: strategy == "all",
					refresh_outputs_from_node: !info_updated,
					estimate_only: Some(true),
					..Default::default()
				};
				let result = owner_api.init_send_tx(keychain_mask, init_args.clone());
				let slate = match result {
					Ok(s) => s,
					Err(e) => match e {
						libwallet::Error::BigAmountError(a, _fee, max_inputs) => {
							debug!("{}", e);
							if args.use_max_amount {
								amount = a;
								init_args = max_retry_args(init_args, amount, max_inputs);
								owner_api.init_send_tx(keychain_mask, init_args)?
							} else {
								return Err(grin_wallet_libwallet::Error::from(e));
							}
						}
						_ => {
							return Err(grin_wallet_libwallet::Error::from(e));
						}
					},
				};
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
		let mut init_args = InitTxArgs {
			src_acct_name: None,
			amount,
			amount_includes_fee: Some(args.amount_includes_fee),
			minimum_confirmations: args.minimum_confirmations,
			max_outputs: args.max_outputs as u32,
			num_change_outputs: args.change_outputs as u32,
			selection_strategy_is_use_all: args.selection_strategy == "all",
			refresh_outputs_from_node: !info_updated,
			target_slate_version: args.target_slate_version,
			payment_proof_recipient_address,
			ttl_blocks: args.ttl_blocks,
			send_args: None,
			late_lock: Some(args.late_lock),
			..Default::default()
		};
		let init_send_tx = |init_args: InitTxArgs| -> Result<Slate, libwallet::Error> {
			let result = owner_api.init_send_tx(keychain_mask, init_args.clone());
			let slate = match result {
				Ok(s) => {
					info!(
						"Tx created: {} grin to {} (strategy '{}')",
						core::amount_to_hr_string(init_args.amount, false),
						dest.as_ref()
							.map(ToString::to_string)
							.unwrap_or_else(|| "no destination".to_string()),
						args.selection_strategy,
					);
					s
				}
				Err(e) => return Err(e),
			};
			Ok(slate)
		};
		slate = match init_send_tx(init_args.clone()) {
			Ok(s) => s,
			Err(e) => match e {
				libwallet::Error::BigAmountError(a, _fee, max_inputs) => {
					debug!("{}", e);
					if args.use_max_amount {
						amount = a;
						init_args = max_retry_args(init_args, amount, max_inputs);
						init_send_tx(init_args).map_err(|e| {
							info!("Tx not created: {}", e);
							Error::from(e)
						})?
					} else {
						info!("Tx not created: {}", e);
						return Err(Error::from(e));
					}
				}
				_ => {
					info!("Tx not created: {}", e);
					return Err(Error::from(e));
				}
			},
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlatepackOut {
	/// Is slatepack encrypted
	pub is_encrypted: bool,
	/// Is slatepack finalized
	pub is_finalized: bool,
	/// File where slatepack is saved
	pub out_file: String,
	/// Slatepack message. Encrypted or not.
	pub message: String,
}

impl fmt::Display for SlatepackOut {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let start_meta = "--------------- SLATEPACK METADATA --------------";
		let meta = format!(
			"Slate encrypted: {}\nSlate finalized: {}\nSlate saved to file: {}",
			self.is_encrypted, self.is_finalized, self.out_file
		);
		let start_slatepack = "-------------- CUT BELOW THIS LINE --------------";
		let end_slatepack = "-------------- CUT ABOVE THIS LINE --------------";
		write!(
			f,
			"{start_meta}\n\n{meta}\n\n{start_slatepack}\n\n{}\n\n{end_slatepack}",
			self.message
		)
	}
}

impl SlatepackOut {
	fn as_json(&self) -> String {
		serde_json::to_string_pretty(&self).unwrap()
	}

	fn render(&self, as_json: bool) -> String {
		if as_json {
			self.as_json()
		} else {
			self.to_string()
		}
	}

	pub fn print(&self, as_json: bool) {
		println!("{}", self.render(as_json));
	}
}

fn slatepack_recipient(dest: Option<&str>) -> Result<Option<SlatepackAddress>, Error> {
	dest.map(SlatepackAddress::try_from)
		.transpose()
		.map_err(Error::from)
}

fn print_contract_status(message: &str, as_json: bool) {
	if as_json {
		eprintln!("{}", message);
	} else {
		println!("{}", message);
	}
}

pub fn print_slatepack<L, C, K>(
	api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	counterparty_addr: Option<SlatepackAddress>,
	out_file: Option<String>,
	as_json: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// For now, we don't compact slates with sl.compact(). We first make them work without compaction.
	// Writing the file, serializing and encrypting can all fail for ordinary reasons, so
	// report them through the normal CLI error path rather than unwrapping.
	let slate_out = prepare_slatepack(api, keychain_mask, &slate, counterparty_addr, out_file)?;
	slate_out.print(as_json);
	Ok(())
}

pub fn prepare_slatepack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	dest: Option<SlatepackAddress>,
	out_file_override: Option<String>,
) -> Result<SlatepackOut, libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// Same as output_slatepack except that we don't write to stdout, care about locking or whether the slate was finalized.

	// Output the slatepack file to stdout and to a file
	let mut message = String::from("");
	let mut tld = String::from("");
	let wallet_inst = owner_api.wallet_inst.clone();
	let config_path = owner_api.config_path();
	controller::owner_single_use(wallet_inst, keychain_mask, config_path, |api, m| {
		// encrypt for recipient by default
		let recipients = match dest.clone() {
			Some(a) => vec![a],
			None => vec![],
		};
		// TODO: what is sender_index?
		message = api.create_slatepack_message(m, &slate, Some(0), recipients)?;
		// Trim the \n at the end.
		let len_withoutcrlf = message.trim_end().len();
		message.truncate(len_withoutcrlf);

		tld = api.get_top_level_directory()?;
		Ok(())
	})?;

	// create a directory to which files will be output
	let slate_dir = format!("{}/{}", tld, "slatepack");
	let _ = std::fs::create_dir_all(slate_dir.clone());
	let out_file_name = match out_file_override {
		None => format!("{}/{}.{}.slatepack", slate_dir, slate.id, slate.state),
		Some(f) => f,
	};

	let mut output = File::create(out_file_name.clone())?;
	output.write_all(&message.as_bytes())?;
	output.sync_all()?;

	// Since we always finalize if we can, we can also use this to know if the tx is finalized
	let is_finalized = can_finalize(slate);

	let slate_out = SlatepackOut {
		is_encrypted: dest.is_some(),
		is_finalized: is_finalized,
		out_file: out_file_name,
		message: message,
	};

	// TODO: We save the slatepack, but it is encrypted for the counterparty. It seems hard to
	// know which slatepack is which if we can't decrypt them. Either add some more metadata
	// to slatepacks e.g. timestamp, counterparty address or save also a version that is encrypted with
	// our own address so we can view it.

	Ok(slate_out)
}

fn parse_slatepack_with_mode<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	filename: Option<String>,
	message: Option<String>,
) -> Result<(Slate, Option<SlatepackAddress>, bool), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let packer = Slatepacker::new(SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key: None,
	});
	let mut slatepack = match filename {
		Some(f) => {
			let pts = PathToSlatepack::new(f.into(), &packer, true);
			pts.get_slatepack(false)?
		}
		None => match message {
			Some(message) => packer.deser_slatepack(message.as_bytes(), false)?,
			None => {
				let msg = "No slate provided via file or direct input";
				return Err(Error::GenericError(msg.into()).into());
			}
		},
	};
	let was_encrypted = slatepack.is_encrypted();
	if was_encrypted {
		let dec_key = owner_api.get_slatepack_secret_key(keychain_mask, 0)?;
		slatepack.try_decrypt_payload(Some(&dec_key))?;
	}
	let slate = packer.get_slate(&slatepack)?;
	Ok((slate, slatepack.sender, was_encrypted))
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
	let (slate, sender, _) =
		parse_slatepack_with_mode(owner_api, keychain_mask, filename, message)?;
	Ok((slate, sender))
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

	if slatepack.is_encrypted() {
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

	// Refresh wallet state from node.
	let (info_updated, update_skipped, _) = owner_api.retrieve_summary_info_with_refresh_status(
		keychain_mask,
		true,
		args.minimum_confirmations,
	)?;
	if !info_updated && !update_skipped {
		warn!("Wallet info update failed: node connection error");
	}

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
					refresh_outputs_from_node: !info_updated,
					estimate_only: Some(true),
					..Default::default()
				};
				let slate = owner_api.init_send_tx(keychain_mask, init_args)?;
				Ok((strategy, slate.amount, slate.fee_fields))
			})
			.collect::<Result<Vec<_>, libwallet::Error>>()?;
		display::estimate(slate.amount, strategies, dark_scheme);
	} else {
		let init_args = InitTxArgs {
			src_acct_name: None,
			amount: 0,
			minimum_confirmations: args.minimum_confirmations,
			max_outputs: args.max_outputs as u32,
			num_change_outputs: 1u32,
			selection_strategy_is_use_all: args.selection_strategy == "all",
			refresh_outputs_from_node: !info_updated,
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

/// Create new contract command arguments
#[derive(Clone)]
pub struct ContractNewArgs {
	/// Address of the counterparty (None = produce an unencrypted slatepack)
	pub counterparty_addr: Option<String>,
	/// Receive amount
	pub receive: Option<u64>,
	/// Send amount
	pub send: Option<u64>,
	/// The human readable account name from which to draw outputs
	/// for the transaction, overriding whatever the active account is as set via the
	/// [`set_active_account`](../grin_wallet_api/owner/struct.Owner.html#method.set_active_account) method.
	pub src_acct_name: Option<String>,
	/// Number of participants in a contract (either 1 or 2)
	pub num_participants: u8,
	/// Show the resulting slatepack as JSON
	pub as_json: bool,
	/// Use the specified inputs (comma separated input commitments)
	pub use_inputs: Option<String>,
	/// Output amounts in nanogrin (one entry per output)
	pub make_outputs: Option<Vec<u64>>,
	/// Minimum number of confirmations required for an input
	pub minimum_confirmations: u64,
	/// Blocks until wallets should stop signing the contract
	pub ttl_blocks: Option<u64>,
	/// Fee rate in nanogrin per unit of transaction weight
	pub fee_rate: Option<u32>,
	/// Override the output Slatepack file
	pub outfile: Option<String>,
	/// Select and lock outputs early
	pub add_outputs: bool,
	/// Early payment proof type
	pub proof_type: Option<ProofType>,
	/// Early payment proof memo
	pub memo: Option<PaymentMemo>,
}

fn contract_proof_args(
	proof_type: Option<ProofType>,
	memo: Option<PaymentMemo>,
	receiving: bool,
) -> Result<ProofArgs, Error> {
	if memo.is_some() && proof_type.is_none() {
		return Err(Error::ArgumentError(
			"--memo requires --proof-type".to_string(),
		));
	}
	if proof_type.is_some() && !receiving {
		return Err(Error::ArgumentError(
			"Early payment proofs require a positive --receive amount".to_string(),
		));
	}
	Ok(match proof_type {
		Some(proof_type) => ProofArgs {
			suppress_proof: false,
			proof_type,
			memo,
			..Default::default()
		},
		None => ProofArgs::default(),
	})
}

fn set_proof_sender(
	proof_args: &mut ProofArgs,
	sender: Option<&SlatepackAddress>,
	fallback: Option<&SlatepackAddress>,
) -> Result<(), Error> {
	if !proof_args.suppress_proof {
		proof_args.sender_address = Some(
			sender
				.or(fallback)
				.ok_or_else(|| {
					Error::ArgumentError(
						"Early payment proofs require a Slatepack sender address".into(),
					)
				})?
				.pub_key,
		);
	}
	Ok(())
}

impl ContractNewArgs {
	fn get_net_change(&self) -> Result<i64, Error> {
		let to_i64 = |v: u64| {
			i64::try_from(v).map_err(|_| Error::ArgumentError(format!("Amount {} is too large", v)))
		};
		match self.receive {
			None => match self.send {
				None => Err(Error::ArgumentError(
					"Send or receive not specified.".into(),
				)),
				Some(v) => Ok(-to_i64(v)?), // negative net change on send
			},
			Some(v) => to_i64(v), // positive net change on receive
		}
	}

	// Create a ContractNewArgsAPI from the ContractNewArgs
	fn to_api_args(&self) -> Result<ContractNewArgsAPI, Error> {
		let net_change = self.get_net_change()?;
		Ok(ContractNewArgsAPI {
			ttl_blocks: self.ttl_blocks,
			setup_args: ContractSetupArgsAPI {
				fee_rate: self.fee_rate,
				src_acct_name: match self.src_acct_name.as_ref() {
					Some(v) => Some(v.to_string()),
					None => None,
				},
				net_change: Some(net_change),
				num_participants: self.num_participants,
				add_outputs: self.add_outputs,
				selection_args: OutputSelectionArgs {
					minimum_confirmations: Some(self.minimum_confirmations),
					use_inputs: match self.use_inputs.as_ref() {
						Some(v) => Some(v.to_string()),
						None => None,
					},
					make_outputs: self.make_outputs.clone(),
					..Default::default()
				},
				proof_args: contract_proof_args(
					self.proof_type,
					self.memo.clone(),
					self.receive.unwrap_or(0) > 0,
				)?,
			},
			..Default::default()
		})
	}
}

pub fn contract_new<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ContractNewArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut contract_new_args = args.to_api_args()?;
	let recipient = slatepack_recipient(args.counterparty_addr.as_deref())?;
	set_proof_sender(
		&mut contract_new_args.setup_args.proof_args,
		recipient.as_ref(),
		None,
	)?;
	let wallet_inst = owner_api.wallet_inst.clone();
	let config_path = owner_api.config_path();
	controller::owner_single_use(wallet_inst, keychain_mask, config_path, |api, m| {
		let slate = api.contract_new(m, &contract_new_args)?;

		print_slatepack(
			api,
			keychain_mask,
			&slate,
			recipient.clone(),
			args.outfile,
			args.as_json,
		)?;

		Ok(())
	})?;

	Ok(())
}

/// Sign contract command argument
#[derive(Clone)]
pub struct ContractSetupArgs {
	/// Address of the counterparty
	pub counterparty_addr: Option<String>,
	/// Receive amount
	pub receive: Option<u64>,
	/// Send amount
	pub send: Option<u64>,
	/// Show the resulting slatepack as JSON
	pub as_json: bool,
	/// Use the specified inputs (comma separated input commitments)
	pub use_inputs: Option<String>,
	/// Output amounts in nanogrin (one entry per output)
	pub make_outputs: Option<Vec<u64>>,
	/// Optional minimum number of confirmations required for an input
	pub minimum_confirmations: Option<u64>,
	/// Fee rate in nanogrin per unit of transaction weight
	pub fee_rate: Option<u32>,
	/// Override the output Slatepack file
	pub outfile: Option<String>,
	/// Early payment proof type
	pub proof_type: Option<ProofType>,
	/// Early payment proof memo
	pub memo: Option<PaymentMemo>,

	// Future features
	/// Whether we should automatically sign a receive of any value
	// pub auto_receive: Option<bool>,
	/// Add outputs
	pub add_outputs: bool, // lock outputs early
}

impl ContractSetupArgs {
	fn get_net_change(&self) -> Result<Option<i64>, Error> {
		if self.receive.is_some() && self.send.is_some() {
			return Err(Error::ArgumentError(
				"Can't pass both --receive and --send parameters.".into(),
			));
		}
		let to_i64 = |v: u64| {
			i64::try_from(v).map_err(|_| Error::ArgumentError(format!("Amount {} is too large", v)))
		};
		let net_change = match (self.receive, self.send) {
			(Some(v), _) => Some(to_i64(v)?),
			(_, Some(v)) => Some(-to_i64(v)?),
			(None, None) => None,
		};
		Ok(net_change)
	}

	// Create a ContractSetupArgsAPI from the ContractSetupArgs
	fn to_api_args(&self) -> Result<ContractSetupArgsAPI, Error> {
		let net_change = self.get_net_change()?;
		Ok(ContractSetupArgsAPI {
			fee_rate: self.fee_rate,
			net_change: net_change,
			add_outputs: self.add_outputs,
			selection_args: OutputSelectionArgs {
				minimum_confirmations: self.minimum_confirmations,
				use_inputs: match self.use_inputs.as_ref() {
					Some(v) => Some(v.to_string()),
					None => None,
				},
				make_outputs: self.make_outputs.clone(),
				..Default::default()
			},
			proof_args: contract_proof_args(
				self.proof_type,
				self.memo.clone(),
				self.receive.unwrap_or(0) > 0,
			)?,
			..Default::default()
		})
	}
}

pub fn contract_sign<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ContractSetupArgs,
	broadcast_tx: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut contract_sign_args = args.to_api_args()?;
	let recipient = slatepack_recipient(args.counterparty_addr.as_deref())?;
	print_contract_status("Paste slatepack:", args.as_json);
	let mut slatepack_msg = String::new();
	io::stdin()
		.read_line(&mut slatepack_msg)
		.map_err(|e| libwallet::Error::GenericError(format!("Failed to read from stdin: {}", e)))?;
	let (mut slate, sender, _) =
		parse_slatepack_with_mode(owner_api, keychain_mask, None, Some(slatepack_msg))?;
	// Bind the proof to the Slatepack sender; --encrypt-for is only the fallback
	set_proof_sender(
		&mut contract_sign_args.proof_args,
		sender.as_ref(),
		recipient.as_ref(),
	)?;
	// Prefer --encrypt-for, then reply to the sender. Without either, use plaintext.
	let recipient = recipient.or(sender);
	let wallet_inst = owner_api.wallet_inst.clone();
	let config_path = owner_api.config_path();
	controller::owner_single_use(wallet_inst, keychain_mask, config_path, |api, m| {
		slate = api.contract_sign(m, &slate, &contract_sign_args)?;

		let slate_out = prepare_slatepack(api, keychain_mask, &slate, recipient, args.outfile)?;

		if broadcast_tx && slate_out.is_finalized {
			if let Err(e) = api.post_tx(keychain_mask, &slate, true) {
				slate_out.print(args.as_json);
				return Err(e);
			}
			if args.as_json {
				slate_out.print(true);
			}
			print_contract_status("Transaction was broadcasted.", args.as_json);
		} else {
			slate_out.print(args.as_json);
		}

		Ok(())
	})?;

	Ok(())
}

#[derive(Clone)]
pub struct ContractViewArgs {
	/// Slatepack file to read the contract from
	pub input_file: Option<String>,
	/// Slatepack message to read the contract from
	pub input_slatepack_message: Option<String>,
}

pub fn contract_view<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ContractViewArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (slate, _, was_encrypted) = parse_slatepack_with_mode(
		owner_api,
		keychain_mask,
		args.input_file,
		args.input_slatepack_message,
	)?;

	let wallet_inst = owner_api.wallet_inst.clone();
	let config_path = owner_api.config_path();
	controller::owner_single_use(wallet_inst, keychain_mask, config_path, |api, m| {
		let view = api.contract_view(m, &slate)?;
		display::contract_view(&slate, &view, was_encrypted);
		Ok(())
	})?;

	Ok(())
}

#[derive(Clone)]
pub struct ContractRevokeArgs {
	/// Id of a transaction we want to cancel
	pub tx_id: u32,
	/// Override the output Slatepack file
	pub outfile: Option<String>,
}

pub fn contract_revoke<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ContractRevokeArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let wallet_inst = owner_api.wallet_inst.clone();
	let config_path = owner_api.config_path();
	controller::owner_single_use(wallet_inst, keychain_mask, config_path, |api, m| {
		let slate_opt = api.contract_revoke(
			m,
			&ContractRevokeArgsAPI {
				tx_id: args.tx_id,
				src_acct_name: None,
			},
		)?;
		if let Some(slate) = slate_opt {
			// A revoke has no counterparty, so write the replacement as plaintext.
			let slate_out = prepare_slatepack(api, keychain_mask, &slate, None, args.outfile)?;
			println!("{}", slate_out);
		} else {
			println!("Contract revoked. No replacement transaction was created.");
		}

		Ok(())
	})?;

	Ok(())
}

#[cfg(test)]
mod send_tests {
	use super::*;

	#[test]
	fn max_retry_updates_args() {
		let args = InitTxArgs {
			amount: 100,
			max_outputs: 500,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		let args = max_retry_args(args, 42, 7);

		assert_eq!(args.amount, 42);
		assert_eq!(args.max_outputs, 7);
		assert!(args.selection_strategy_is_use_all);
	}

	#[test]
	fn max_estimate_uses_all() {
		assert_eq!(estimate_strategies(true), &["all"]);
		assert_eq!(estimate_strategies(false), &["smallest", "all"]);
	}
}

#[cfg(test)]
mod contract_tests {
	use super::*;
	use ed25519_dalek::{SigningKey, VerifyingKey};

	#[test]
	fn invalid_recipient() {
		assert!(slatepack_recipient(Some("invalid")).is_err());
		assert!(slatepack_recipient(None).unwrap().is_none());
	}

	#[test]
	fn finalized_json() {
		let output = SlatepackOut {
			is_encrypted: false,
			is_finalized: true,
			out_file: "slatepack/test.S3.slatepack".to_string(),
			message: "BEGINSLATEPACK. test. ENDSLATEPACK.".to_string(),
		};

		let value: serde_json::Value = serde_json::from_str(&output.render(true)).unwrap();
		assert_eq!(value["is_finalized"], true);
		assert_eq!(value["message"], output.message);
	}

	#[test]
	fn slatepack_encryption() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let key = SigningKey::from_bytes(&[1; 32]);
		let address = SlatepackAddress::new(&VerifyingKey::from(&key));
		let slate = Slate::blank(2, false);

		let plain = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		})
		.create_slatepack(&slate)
		.unwrap();
		assert!(!plain.is_encrypted());

		let encrypted = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![address],
			dec_key: None,
		})
		.create_slatepack(&slate)
		.unwrap();
		assert!(encrypted.is_encrypted());

		let mut invalid = serde_json::to_value(&plain).unwrap();
		invalid["mode"] = serde_json::json!(2);
		let data = serde_json::to_vec(&invalid).unwrap();
		let packer = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		});
		assert!(matches!(
			packer.deser_slatepack(&data, false),
			Err(libwallet::Error::SlatepackDeser(message))
				if message.contains("Unsupported Slatepack mode: 2")
		));
	}

	#[test]
	fn contract_sign_args() {
		let args = ContractSetupArgs {
			counterparty_addr: None,
			receive: Some(1),
			send: None,
			as_json: false,
			use_inputs: Some("commitment".to_string()),
			make_outputs: None,
			minimum_confirmations: None,
			fee_rate: Some(2),
			outfile: None,
			add_outputs: false,
			proof_type: Some(ProofType::Invoice),
			memo: Some(PaymentMemo::new("payment".into()).unwrap()),
		};
		let mut api_args = args.to_api_args().unwrap();
		let key = SigningKey::from_bytes(&[1; 32]);
		let sender = SlatepackAddress {
			hrp: "tgrin".to_string(),
			pub_key: VerifyingKey::from(&key),
		};
		let fallback = SlatepackAddress {
			hrp: "tgrin".to_string(),
			pub_key: VerifyingKey::from(&SigningKey::from_bytes(&[2; 32])),
		};
		set_proof_sender(&mut api_args.proof_args, Some(&sender), Some(&fallback)).unwrap();
		assert_eq!(api_args.fee_rate, Some(2));
		assert_eq!(api_args.proof_args.proof_type, ProofType::Invoice);
		assert_eq!(api_args.proof_args.sender_address, Some(sender.pub_key));
		assert_eq!(
			api_args.proof_args.memo.as_ref().map(PaymentMemo::as_str),
			Some("payment")
		);
		assert_eq!(
			api_args.selection_args.use_inputs.as_deref(),
			Some("commitment")
		);

		let mut invalid = args;
		invalid.receive = None;
		assert!(matches!(
			invalid.to_api_args(),
			Err(Error::ArgumentError(message))
				if message == "Early payment proofs require a positive --receive amount"
		));
		invalid.receive = Some(0);
		assert!(matches!(
			invalid.to_api_args(),
			Err(Error::ArgumentError(message))
				if message == "Early payment proofs require a positive --receive amount"
		));
		invalid.proof_type = None;
		assert!(matches!(
			invalid.to_api_args(),
			Err(Error::ArgumentError(message)) if message == "--memo requires --proof-type"
		));
	}

	#[test]
	fn contract_new_args() {
		let args = ContractNewArgs {
			counterparty_addr: None,
			receive: Some(1),
			send: None,
			src_acct_name: None,
			num_participants: 2,
			as_json: false,
			use_inputs: Some("commitment".to_string()),
			make_outputs: None,
			minimum_confirmations: 1,
			ttl_blocks: None,
			fee_rate: None,
			outfile: None,
			add_outputs: false,
			proof_type: Some(ProofType::SenderNonce),
			memo: Some(PaymentMemo::new("payment".into()).unwrap()),
		};
		let api_args = args.to_api_args().unwrap();
		assert_eq!(
			api_args.setup_args.proof_args.proof_type,
			ProofType::SenderNonce
		);
		assert_eq!(
			api_args
				.setup_args
				.proof_args
				.memo
				.as_ref()
				.map(PaymentMemo::as_str),
			Some("payment")
		);
		assert_eq!(
			api_args.setup_args.selection_args.use_inputs.as_deref(),
			Some("commitment")
		);
	}
}
