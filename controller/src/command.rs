// Copyright 2019 The Grin Developers
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
use crate::config::{TorConfig, WalletConfig, WALLET_CONFIG_FILE_NAME};
use crate::core::{core, global};
use crate::error::{Error, ErrorKind};
use crate::impls::{create_sender, KeybaseAllChannels, SlateGetter as _, SlateReceiver as _};
use crate::impls::{PathToSlate, SlatePutter};
use crate::keychain;
use crate::libwallet::{InitTxArgs, IssueInvoiceTxArgs, NodeClient, WalletInst, WalletLCProvider};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ZeroingString};
use crate::{controller, display};
use serde_json as json;
use std::fs::File;
use std::io::Write;
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
	pub chain_type: global::ChainTypes,
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
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	g_args: &GlobalArgs,
	args: InitArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut w_lock = wallet.lock();
	let p = w_lock.lc_provider()?;
	p.create_config(
		&g_args.chain_type,
		WALLET_CONFIG_FILE_NAME,
		None,
		None,
		None,
	)?;
	p.create_wallet(
		None,
		args.recovery_phrase,
		args.list_length,
		args.password.clone(),
		false,
	)?;

	let m = p.get_mnemonic(None, args.password)?;
	show_recovery_phrase(m);
	Ok(())
}

/// Argument for recover
pub struct RecoverArgs {
	pub recovery_phrase: Option<ZeroingString>,
	pub passphrase: ZeroingString,
}

pub fn recover<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	args: RecoverArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut w_lock = wallet.lock();
	let p = w_lock.lc_provider()?;
	match args.recovery_phrase {
		None => {
			let m = p.get_mnemonic(None, args.passphrase)?;
			show_recovery_phrase(m);
		}
		Some(phrase) => p.recover_from_mnemonic(phrase, args.passphrase)?,
	}
	Ok(())
}

/// Arguments for listen command
pub struct ListenArgs {
	pub method: String,
}

pub fn listen<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	args: &ListenArgs,
	g_args: &GlobalArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let res = match args.method.as_str() {
		"http" => controller::foreign_listener(
			wallet.clone(),
			keychain_mask,
			&config.api_listen_addr(),
			g_args.tls_conf.clone(),
			tor_config.use_tor_listener,
		),
		"keybase" => KeybaseAllChannels::new()?.listen(
			config.clone(),
			g_args.password.clone().unwrap(),
			&g_args.account,
			g_args.node_api_secret.clone(),
		),
		method => {
			return Err(ErrorKind::ArgumentError(format!(
				"No listener for method \"{}\".",
				method
			))
			.into());
		}
	};

	if let Err(e) = res {
		return Err(ErrorKind::LibWallet(e.kind(), e.cause_string()).into());
	}
	Ok(())
}

pub fn owner_api<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<SecretKey>,
	config: &WalletConfig,
	g_args: &GlobalArgs,
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
		wallet,
		km,
		config.owner_api_listen_addr().as_str(),
		g_args.api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign.clone(),
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
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: AccountArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	if args.create.is_none() {
		let res = controller::owner_single_use(wallet, keychain_mask, |api, m| {
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
		let res = controller::owner_single_use(wallet, keychain_mask, |api, m| {
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
pub struct SendArgs {
	pub amount: u64,
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub method: String,
	pub dest: String,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
}

pub fn send<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: SendArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
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
						..Default::default()
					};
					let slate = api.init_send_tx(m, init_args).unwrap();
					(strategy, slate.amount, slate.fee)
				})
				.collect();
			display::estimate(args.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: args.amount,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: args.change_outputs as u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				message: args.message.clone(),
				target_slate_version: args.target_slate_version,
				send_args: None,
				..Default::default()
			};
			let result = api.init_send_tx(m, init_args);
			let mut slate = match result {
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

			match args.method.as_str() {
				"file" => {
					PathToSlate((&args.dest).into()).put_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, 0)?;
					return Ok(());
				}
				"self" => {
					api.tx_lock_outputs(m, &slate, 0)?;
					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					controller::foreign_single_use(wallet, km, |api| {
						slate = api.receive_tx(&slate, Some(&args.dest), None)?;
						Ok(())
					})?;
				}
				method => {
					let sender = create_sender(method, &args.dest, tor_config)?;
					slate = sender.send_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, 0)?;
				}
			}

			api.verify_slate_messages(m, &slate).map_err(|e| {
				error!("Error validating participant messages: {}", e);
				e
			})?;
			slate = api.finalize_tx(m, &slate)?;
			let result = api.post_tx(m, &slate.tx, args.fluff);
			match result {
				Ok(_) => {
					info!("Tx sent ok",);
					return Ok(());
				}
				Err(e) => {
					error!("Tx sent fail: {}", e);
					return Err(e);
				}
			}
		}
		Ok(())
	})?;
	Ok(())
}

/// Receive command argument
pub struct ReceiveArgs {
	pub input: String,
	pub message: Option<String>,
}

pub fn receive<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = PathToSlate((&args.input).into()).get_tx()?;
	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};
	controller::foreign_single_use(wallet, km, |api| {
		if let Err(e) = api.verify_slate_messages(&slate) {
			error!("Error validating participant messages: {}", e);
			return Err(e);
		}
		slate = api.receive_tx(&slate, Some(&g_args.account), args.message.clone())?;
		Ok(())
	})?;
	PathToSlate(format!("{}.response", args.input).into()).put_tx(&slate)?;
	info!(
		"Response file {}.response generated, and can be sent back to the transaction originator.",
		args.input
	);
	Ok(())
}

/// Finalize command args
pub struct FinalizeArgs {
	pub input: String,
	pub fluff: bool,
	pub nopost: bool,
	pub dest: Option<String>,
}

pub fn finalize<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: FinalizeArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = PathToSlate((&args.input).into()).get_tx()?;

	// Rather than duplicating the entire command, we'll just
	// try to determine what kind of finalization this is
	// based on the slate contents
	// for now, we can tell this is an invoice transaction
	// if the receipient (participant 1) hasn't completed sigs
	let part_data = slate.participant_with_id(1);
	let is_invoice = {
		match part_data {
			None => {
				error!("Expected slate participant data missing");
				return Err(ErrorKind::ArgumentError(
					"Expected Slate participant data missing".into(),
				))?;
			}
			Some(p) => !p.is_complete(),
		}
	};

	if is_invoice {
		let km = match keychain_mask.as_ref() {
			None => None,
			Some(&m) => Some(m.to_owned()),
		};
		controller::foreign_single_use(wallet.clone(), km, |api| {
			if let Err(e) = api.verify_slate_messages(&slate) {
				error!("Error validating participant messages: {}", e);
				return Err(e);
			}
			slate = api.finalize_invoice_tx(&mut slate)?;
			Ok(())
		})?;
	} else {
		controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(e);
			}
			slate = api.finalize_tx(m, &mut slate)?;
			Ok(())
		})?;
	}

	if !args.nopost {
		controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
			let result = api.post_tx(m, &slate.tx, args.fluff);
			match result {
				Ok(_) => {
					info!(
						"Transaction sent successfully, check the wallet again for confirmation."
					);
					Ok(())
				}
				Err(e) => {
					error!("Tx not sent: {}", e);
					Err(e)
				}
			}
		})?;
	}

	if args.dest.is_some() {
		PathToSlate((&args.dest.unwrap()).into()).put_tx(&slate)?;
	}

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// output file
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
}

pub fn issue_invoice_tx<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
		let slate = api.issue_invoice_tx(m, args.issue_args)?;
		let mut tx_file = File::create(args.dest.clone())?;
		tx_file.write_all(json::to_string(&slate).unwrap().as_bytes())?;
		tx_file.sync_all()?;
		Ok(())
	})?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub method: String,
	pub dest: String,
	pub max_outputs: usize,
	pub input: String,
	pub estimate_selection_strategies: bool,
}

/// Process invoice
pub fn process_invoice<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: ProcessInvoiceArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let slate = PathToSlate((&args.input).into()).get_tx()?;
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
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
					(strategy, slate.amount, slate.fee)
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
				message: args.message.clone(),
				send_args: None,
				..Default::default()
			};
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(e);
			}
			let result = api.process_invoice_tx(m, &slate, init_args);
			let mut slate = match result {
				Ok(s) => {
					info!(
						"Invoice processed: {} grin to {} (strategy '{}')",
						core::amount_to_hr_string(slate.amount, false),
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

			match args.method.as_str() {
				"file" => {
					let slate_putter = PathToSlate((&args.dest).into());
					slate_putter.put_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, 0)?;
				}
				"self" => {
					api.tx_lock_outputs(m, &slate, 0)?;
					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					controller::foreign_single_use(wallet, km, |api| {
						slate = api.finalize_invoice_tx(&slate)?;
						Ok(())
					})?;
				}
				method => {
					let sender = create_sender(method, &args.dest, tor_config)?;
					slate = sender.send_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, 0)?;
				}
			}
		}
		Ok(())
	})?;
	Ok(())
}
/// Info command args
pub struct InfoArgs {
	pub minimum_confirmations: u64,
}

pub fn info<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
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
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
		let (validated, wallet_info) =
			api.retrieve_summary_info(m, true, args.minimum_confirmations)?;
		display::info(&g_args.account, &wallet_info, validated, dark_scheme);
		Ok(())
	})?;
	Ok(())
}

pub fn outputs<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
		let res = api.node_height(m)?;
		let (validated, outputs) = api.retrieve_outputs(m, g_args.show_spent, true, None)?;
		display::outputs(&g_args.account, res.height, validated, outputs, dark_scheme)?;
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
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
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
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
		let res = api.node_height(m)?;
		let (validated, txs) = api.retrieve_txs(m, true, args.id, args.tx_slate_id)?;
		let include_status = !args.id.is_some() && !args.tx_slate_id.is_some();
		display::txs(
			&g_args.account,
			res.height,
			validated,
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
			display::outputs(&g_args.account, res.height, validated, outputs, dark_scheme)?;
			// should only be one here, but just in case
			for tx in txs {
				display::tx_messages(&tx, dark_scheme)?;
			}
		}

		Ok(())
	})?;
	Ok(())
}

/// Post
pub struct PostArgs {
	pub input: String,
	pub fluff: bool,
}

pub fn post<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: PostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let slate = PathToSlate((&args.input).into()).get_tx()?;

	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
		api.post_tx(m, &slate.tx, args.fluff)?;
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
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: RepostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
		let (_, txs) = api.retrieve_txs(m, true, Some(args.id), None)?;
		let stored_tx = api.get_stored_tx(m, &txs[0])?;
		if stored_tx.is_none() {
			error!(
				"Transaction with id {} does not have transaction data. Not reposting.",
				args.id
			);
			return Ok(());
		}
		match args.dump_file {
			None => {
				if txs[0].confirmed {
					error!(
						"Transaction with id {} is confirmed. Not reposting.",
						args.id
					);
					return Ok(());
				}
				api.post_tx(m, &stored_tx.unwrap(), args.fluff)?;
				info!("Reposted transaction at {}", args.id);
				return Ok(());
			}
			Some(f) => {
				let mut tx_file = File::create(f.clone())?;
				tx_file.write_all(json::to_string(&stored_tx).unwrap().as_bytes())?;
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
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: CancelArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
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
}

pub fn scan<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: CheckArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(wallet.clone(), keychain_mask, |api, m| {
		warn!("Starting output scan ...",);
		let result = api.scan(m, args.start_height, args.delete_unconfirmed);
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
