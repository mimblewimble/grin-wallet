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
use crate::error::{Error, ErrorKind};
use crate::impls::PathToSlatepack;
use crate::impls::SlateGetter as _;
use crate::keychain;
use crate::libwallet::{
	self, InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, Slate, SlateState, Slatepack,
	SlatepackAddress, Slatepacker, SlatepackerArgs, TxFlow, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ZeroingString};
use crate::{controller, display};
use serde_json as json;
use std::convert::TryFrom;
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

/// Arguments for listen command
pub struct ListenArgs {}

pub fn listen<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	_args: &ListenArgs,
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
	let config = config.clone();
	let tor_config = tor_config.clone();
	let g_args = g_args.clone();
	let api_thread = thread::Builder::new()
		.name("wallet-http-listener".to_string())
		.spawn(move || {
			let res = controller::foreign_listener(
				wallet_inst,
				keychain_mask,
				&config.api_listen_addr(),
				g_args.tls_conf.clone(),
				tor_config.use_tor_listener,
				test_mode,
				Some(tor_config.clone()),
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
				return Err(ErrorKind::ListenerError.into());
			}
		}
	}
	Ok(())
}

pub fn owner_api<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<SecretKey>,
	config: &WalletConfig,
	tor_config: &TorConfig,
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
		owner_api.wallet_inst.clone(),
		km,
		config.owner_api_listen_addr().as_str(),
		g_args.api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign,
		Some(tor_config.clone()),
		test_mode,
	);
	if let Err(e) = res {
		return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
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
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let acct_mappings = api.accounts(m)?;
			// give logging thread a moment to catch up
			thread::sleep(Duration::from_millis(200));
			display::accounts(acct_mappings);
			Ok(())
		});
		if let Err(e) = res {
			error!("Error listing accounts: {}", e);
			return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
		}
	} else {
		let label = args.create.unwrap();
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			api.create_account_path(m, &label)?;
			thread::sleep(Duration::from_millis(200));
			info!("Account: '{}' Created!", label);
			Ok(())
		});
		if let Err(e) = res {
			thread::sleep(Duration::from_millis(200));
			error!("Error creating account '{}': {}", label, e);
			return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
		}
	}
	Ok(())
}

/// Arguments for the send command
#[derive(Clone)]
pub struct SendArgs {
	pub amount: u64,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub late_lock: bool,
	pub dest: String,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
	pub payment_proof_address: Option<SlatepackAddress>,
	pub ttl_blocks: Option<u64>,
	pub skip_tor: bool,
	pub outfile: Option<String>,
	pub is_multisig: Option<bool>,
	pub derive_path: Option<u32>,
}

pub fn send<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: SendArgs,
	dark_scheme: bool,
	test_mode: bool,
	tx_flow: TxFlow,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = Slate::blank(2, tx_flow.clone());
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let strategies = vec!["smallest", "all"]
				.into_iter()
				.map(|strategy| {
					let init_args = InitTxArgs {
						src_acct_name: None,
						amount: args.amount,
						minimum_confirmations: args.minimum_confirmations,
						max_outputs: args.max_outputs as u32,
						num_change_outputs: args.change_outputs as u32,
						selection_strategy_is_use_all: strategy == "all",
						estimate_only: Some(true),
						is_multisig: args.is_multisig,
						..Default::default()
					};
					let slate = match tx_flow {
						TxFlow::Standard => api.init_send_tx(m, init_args)?,
						TxFlow::Atomic => api.init_atomic_swap(m, init_args)?,
						_ => api.init_send_tx(m, init_args)?,
					};

					Ok((strategy, slate.amount, slate.fee_fields))
				})
				.collect::<Result<Vec<_>, grin_wallet_libwallet::Error>>()?;
			display::estimate(args.amount, strategies, dark_scheme);
			return Ok(());
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: args.amount,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: args.change_outputs as u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				target_slate_version: args.target_slate_version,
				payment_proof_recipient_address: args.payment_proof_address.clone(),
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				late_lock: Some(args.late_lock),
				is_multisig: args.is_multisig,
				..Default::default()
			};
			let result = match tx_flow {
				TxFlow::Standard => api.init_send_tx(m, init_args),
				TxFlow::Atomic => api.init_atomic_swap(m, init_args),
				_ => api.init_send_tx(m, init_args),
			};
			slate = match result {
				Ok(s) => {
					info!(
						"Tx created: {} grin to {} (strategy '{}')",
						core::amount_to_hr_string(args.amount, false),
						args.dest,
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(e);
				}
			};
		}
		Ok(())
	})?;

	if args.estimate_selection_strategies {
		return Ok(());
	}

	let tor_config = match tor_config {
		Some(mut c) => {
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	let res = try_slatepack_sync_workflow(&slate, &args.dest, tor_config, None, false, test_mode);

	match res {
		Ok(Some(s)) => {
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				api.tx_lock_outputs(m, &s)?;
				let ret_slate = api.finalize_tx(m, &s)?;
				let result = api.post_tx(m, &ret_slate, args.fluff);
				match result {
					Ok(_) => {
						println!("Tx sent successfully",);
						Ok(())
					}
					Err(e) => {
						error!("Tx sent fail: {}", e);
						Err(e.into())
					}
				}
			})?;
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				args.dest.as_str(),
				args.outfile,
				true,
				false,
			)?;
		}
		Err(e) => return Err(e.into()),
	}
	Ok(())
}

pub fn output_slatepack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	dest: &str,
	out_file_override: Option<String>,
	lock: bool,
	finalizing: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// Output the slatepack file to stdout and to a file
	let mut message = String::from("");
	let mut address = None;
	let mut tld = String::from("");
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		address = match SlatepackAddress::try_from(dest) {
			Ok(a) => Some(a),
			Err(_) => None,
		};
		// encrypt for recipient by default
		let recipients = match address.clone() {
			Some(a) => vec![a],
			None => vec![],
		};
		message = api.create_slatepack_message(m, &slate, Some(0), recipients)?;
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

	if lock {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			api.tx_lock_outputs(m, &slate)?;
			Ok(())
		})?;
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
	if address.is_some() {
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
			let mut sl = None;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let dec_key = api.get_slatepack_secret_key(m, 0)?;
				let packer = Slatepacker::new(SlatepackerArgs {
					sender: None,
					recipients: vec![],
					dec_key: Some(&dec_key),
				});
				let pts = PathToSlatepack::new(f.into(), &packer, true);
				sl = Some(pts.get_tx()?.0);
				ret_address = pts.get_slatepack(true)?.sender;
				Ok(())
			})?;
			sl
		}
		None => None,
	};

	let slate = match slate {
		Some(s) => s,
		None => {
			// try and parse directly from input_slatepack_message
			let mut slate = Slate::blank(2, TxFlow::Standard);
			match message {
				Some(message) => {
					controller::owner_single_use(
						None,
						keychain_mask,
						Some(owner_api),
						|api, m| {
							slate =
								api.slate_from_slatepack_message(m, message.clone(), vec![0])?;
							let slatepack =
								api.decode_slatepack_message(m, message.clone(), vec![0])?;
							ret_address = slatepack.sender;
							Ok(())
						},
					)?;
				}
				None => {
					let msg = "No slate provided via file or direct input";
					return Err(ErrorKind::GenericError(msg.into()).into());
				}
			}
			slate
		}
	};
	Ok((slate, ret_address))
}

/// Receive command argument
#[derive(Clone)]
pub struct ReceiveArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub skip_tor: bool,
	pub outfile: Option<String>,
}

pub fn receive<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
	tor_config: Option<TorConfig>,
	test_mode: bool,
	tx_flow: TxFlow,
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

	let tor_config = match tor_config {
		Some(mut c) => {
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		slate = match tx_flow {
			TxFlow::Standard => api.receive_tx(&slate, Some(&g_args.account), None)?,
			TxFlow::Atomic => api.receive_atomic_tx(&slate, Some(&g_args.account), None)?,
			_ => {
				return Err(
					libwallet::ErrorKind::GenericError("Invalid transaction flow".into()).into(),
				)
			}
		};
		Ok(())
	})?;

	let dest = match ret_address {
		Some(a) => String::try_from(&a).unwrap(),
		None => String::from(""),
	};

	let res = try_slatepack_sync_workflow(&slate, &dest, tor_config, None, true, test_mode);

	match res {
		Ok(Some(_)) => {
			println!();
			println!(
				"Transaction recieved and sent back to sender at {} for finalization.",
				dest
			);
			println!();
			Ok(())
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				&dest,
				args.outfile,
				false,
				false,
			)?;
			Ok(())
		}
		Err(e) => Err(e.into()),
	}
}
pub fn countersign_atomic<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ReceiveArgs,
	tor_config: Option<TorConfig>,
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

	let tor_config = match tor_config {
		Some(mut c) => {
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		slate = api.countersign_atomic_swap(&slate, m, None)?;
		Ok(())
	})?;

	let dest = match ret_address {
		Some(a) => String::try_from(&a).unwrap(),
		None => String::from(""),
	};

	let res = try_slatepack_sync_workflow(&slate, &dest, tor_config, None, true, test_mode);

	match res {
		Ok(Some(_)) => {
			println!();
			println!(
				"Transaction countersigned and sent back to {} for finalization.",
				dest
			);
			println!();
			Ok(())
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				&dest,
				args.outfile,
				false,
				false,
			)?;
			Ok(())
		}
		Err(e) => Err(e.into()),
	}
}

/// Process Multisig command arguments
#[derive(Clone)]
pub struct MultisigArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub skip_tor: bool,
	pub outfile: Option<String>,
}

pub fn process_multisig<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: MultisigArgs,
	tor_config: Option<TorConfig>,
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

	let tor_config = match tor_config {
		Some(mut c) => {
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	controller::owner_single_use(
		Some(owner_api.wallet_inst.clone()),
		keychain_mask,
		Some(owner_api),
		|api, m| {
			slate = api.process_multisig_tx(m, &slate)?;
			Ok(())
		},
	)?;

	let dest = match ret_address {
		Some(a) => String::try_from(&a).unwrap(),
		None => String::from(""),
	};

	let res = try_slatepack_sync_workflow(&slate, &dest, tor_config, None, true, test_mode);

	match res {
		Ok(Some(_)) => {
			println!();
			println!(
				"Transaction multisig bulletproof processed and sent back to recipient at {} for first round of finalization.",
				dest
			);
			println!();
			Ok(())
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				&dest,
				args.outfile,
				false,
				false,
			)?;
			Ok(())
		}
		Err(e) => Err(e.into()),
	}
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
			Some(mes) => {
				let mut sp = Slatepack::default();
				controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
					sp = api.decode_slatepack_message(m, mes, vec![])?;
					Ok(())
				})?;
				sp
			}
			None => {
				return Err(ErrorKind::ArgumentError("Invalid Slatepack Input".into()).into());
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
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let dec_key = api.get_slatepack_secret_key(m, 0)?;
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
			Ok(())
		})?;
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
}

pub fn finalize<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: FinalizeArgs,
	tx_flow: TxFlow,
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
		controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		})?;
	} else {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			slate = match tx_flow {
				TxFlow::Standard => api.finalize_tx(m, &slate)?,
				TxFlow::Atomic => api.finalize_atomic_swap(m, &slate)?,
				_ => {
					return Err(libwallet::ErrorKind::GenericError(
						"invalid transaction flow".into(),
					)
					.into())
				}
			};
			Ok(())
		})?;
	}

	if !&args.nopost {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let result = api.post_tx(m, &slate, args.fluff);
			match result {
				Ok(_) => {
					info!(
						"Transaction sent successfully, check the wallet again for confirmation."
					);
					println!("Transaction posted");
					Ok(())
				}
				Err(e) => {
					error!("Tx not sent: {}", e);
					Err(e)
				}
			}
		})?;
	}

	println!("Transaction finalized successfully");

	if slate
		.participant_data
		.iter()
		.fold(false, |t, d| t | d.tau_x.is_some())
	{
		info!(
			"Transaction multisig identifier: {}",
			slate.create_multisig_id().to_bip_32_string()
		);
		info!("Use the identifier to select the multisig output in future transactions");
	}

	output_slatepack(
		owner_api,
		keychain_mask,
		&slate,
		"",
		args.outfile,
		false,
		true,
	)?;

	Ok(())
}

/// Recover atomic secret args
#[derive(Clone)]
pub struct RecoverAtomicArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub outfile: Option<String>,
}

/// Recover the atomic secret from an adaptor signature and kernel excess signature
pub fn recover_atomic_secret<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: RecoverAtomicArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (slate, _ret_address) = parse_slatepack(
		owner_api,
		keychain_mask,
		args.input_file.clone(),
		args.input_slatepack_message.clone(),
	)?;
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.recover_atomic_secret(m, &slate);
		match result {
			Ok(_) => {
				info!("Atomic nonce recovered successfully.");
				Ok(())
			}
			Err(e) => {
				error!("Tx not sent: {}", e);
				Err(e)
			}
		}
	})?;

	println!("Transaction finalized successfully");
	Ok(())
}

/// Get atomic secrets args
#[derive(Clone)]
pub struct GetAtomicSecretsArgs {
	pub id: u32,
	pub amount: f64,
}

/// Get atomic secrets from storage to recover funds on the other chain
pub fn get_atomic_secrets<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: GetAtomicSecretsArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result =
			api.get_atomic_secrets(m, args.id, (args.amount * (10_u64.pow(9) as f64)) as u64);
		match result {
			Ok(_) => {
				info!("Atomic nonces recovered successfully.");
				Ok(())
			}
			Err(e) => {
				error!("Tx not sent: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// Slatepack address
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
	/// output file override
	pub outfile: Option<String>,
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
	let issue_args = args.issue_args.clone();

	let mut slate = Slate::blank(2, TxFlow::Standard);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		slate = api.issue_invoice_tx(m, issue_args)?;
		Ok(())
	})?;

	output_slatepack(
		owner_api,
		keychain_mask,
		&slate,
		args.dest.as_str(),
		args.outfile,
		false,
		false,
	)?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub ret_address: Option<SlatepackAddress>,
	pub max_outputs: usize,
	pub slate: Slate,
	pub estimate_selection_strategies: bool,
	pub ttl_blocks: Option<u64>,
	pub skip_tor: bool,
	pub outfile: Option<String>,
}

/// Process invoice
pub fn process_invoice<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: ProcessInvoiceArgs,
	dark_scheme: bool,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = args.slate.clone();
	let dest = match args.ret_address.clone() {
		Some(a) => String::try_from(&a).unwrap(),
		None => String::from(""),
	};

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
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
					let slate = api.init_send_tx(m, init_args).unwrap();
					(strategy, slate.amount, slate.fee_fields)
				})
				.collect();
			display::estimate(slate.amount, strategies, dark_scheme);
			return Ok(());
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
			let result = api.process_invoice_tx(m, &slate, init_args);
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
					return Err(e);
				}
			};
		}
		Ok(())
	})?;

	let tor_config = match tor_config {
		Some(mut c) => {
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	let res = try_slatepack_sync_workflow(&slate, &dest, tor_config, None, true, test_mode);

	match res {
		Ok(Some(_)) => {
			println!();
			println!(
				"Transaction paid and sent back to initiator at {} for finalization.",
				dest
			);
			println!();
			Ok(())
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				&dest,
				args.outfile,
				true,
				false,
			)?;
			Ok(())
		}
		Err(e) => Err(e.into()),
	}
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (validated, wallet_info) =
			api.retrieve_summary_info(m, true, args.minimum_confirmations)?;
		display::info(
			&g_args.account,
			&wallet_info,
			validated || updater_running,
			dark_scheme,
		);
		Ok(())
	})?;
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		let (validated, outputs) = api.retrieve_outputs(m, g_args.show_spent, true, None)?;
		display::outputs(
			&g_args.account,
			res.height,
			validated || updater_running,
			outputs,
			dark_scheme,
		)?;
		Ok(())
	})?;
	Ok(())
}

/// Txs command args
pub struct TxsArgs {
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		let (validated, txs) = api.retrieve_txs(m, true, args.id, args.tx_slate_id)?;
		let include_status = !args.id.is_some() && !args.tx_slate_id.is_some();
		display::txs(
			&g_args.account,
			res.height,
			validated || updater_running,
			&txs,
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
			let (_, outputs) = api.retrieve_outputs(m, true, false, id)?;
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
	})?;
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		api.post_tx(m, &slate, fluff)?;
		info!("Posted transaction");
		return Ok(());
	})?;
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let stored_tx_slate = match api.get_stored_tx(m, Some(args.id), None)? {
			None => {
				error!(
					"Transaction with id {} does not have transaction data. Not reposting.",
					args.id
				);
				return Ok(());
			}
			Some(s) => s,
		};
		let (_, txs) = api.retrieve_txs(m, true, Some(args.id), None)?;
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

				match api.post_tx(m, &stored_tx_slate, args.fluff) {
					Ok(_) => info!("Reposted transaction at {}", args.id),
					Err(e) => error!("Could not repost transaction at {}. Reason: {}", args.id, e),
				}
				return Ok(());
			}
			Some(f) => {
				let mut tx_file = File::create(f.clone())?;
				tx_file.write_all(
					json::to_string(&stored_tx_slate.tx.unwrap())
						.unwrap()
						.as_bytes(),
				)?;
				tx_file.sync_all()?;
				info!("Dumped transaction data for tx {} to {}", args.id, f);
				return Ok(());
			}
		}
	})?;
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.cancel_tx(m, args.tx_id, args.tx_slate_id);
		match result {
			Ok(_) => {
				info!("Transaction {} Cancelled", args.tx_id_string);
				Ok(())
			}
			Err(e) => {
				error!("TX Cancellation failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let tip_height = api.node_height(m)?.height;
		let start_height = match args.backwards_from_tip {
			Some(b) => tip_height.saturating_sub(b),
			None => match args.start_height {
				Some(s) => s,
				None => 1,
			},
		};
		warn!("Starting output scan from height {} ...", start_height);
		let result = api.scan(m, Some(start_height), args.delete_unconfirmed);
		match result {
			Ok(_) => {
				warn!("Wallet check complete",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet check failed: {}", e);
				error!("Backtrace: {}", e.backtrace().unwrap());
				Err(e)
			}
		}
	})?;
	Ok(())
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		// Just address at derivation index 0 for now
		let address = api.get_slatepack_address(m, 0)?;
		println!();
		println!("Address for account - {}", g_args.account);
		println!("-------------------------------------");
		println!("{}", address);
		println!();
		Ok(())
	})?;
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.retrieve_payment_proof(m, true, args.id, args.tx_slate_id);
		match result {
			Ok(p) => {
				// actually export proof
				let mut proof_file = File::create(args.output_file.clone())?;
				proof_file.write_all(json::to_string_pretty(&p).unwrap().as_bytes())?;
				proof_file.sync_all()?;
				warn!("Payment proof exported to {}", args.output_file);
				Ok(())
			}
			Err(e) => {
				error!("Proof export failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
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
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let mut proof_f = match File::open(&args.input_file) {
			Ok(p) => p,
			Err(e) => {
				let msg = format!("{}", e);
				error!(
					"Unable to open payment proof file at {}: {}",
					args.input_file, e
				);
				return Err(libwallet::ErrorKind::PaymentProofParsing(msg).into());
			}
		};
		let mut proof = String::new();
		proof_f.read_to_string(&mut proof)?;
		// read
		let proof: PaymentProof = match json::from_str(&proof) {
			Ok(p) => p,
			Err(e) => {
				let msg = format!("{}", e);
				error!("Unable to parse payment proof file: {}", e);
				return Err(libwallet::ErrorKind::PaymentProofParsing(msg).into());
			}
		};
		let result = api.verify_payment_proof(m, &proof);
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
				Err(e)
			}
		}
	})?;
	Ok(())
}
