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
use crate::apiwallet::Owner;
use crate::config::{TorConfig, WalletConfig, WALLET_CONFIG_FILE_NAME};
use crate::core::{core, global};
use crate::error::{Error, ErrorKind};
use crate::impls::{create_sender, SlateGetter as _, SlateSender as _};
use crate::impls::{HttpSlateSender, PathToSlate, SlatePutter};
use crate::keychain;
use crate::libwallet::{
	self, InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, Slate, SlateVersion,
	SlatepackAddress, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ZeroingString};
use crate::{controller, display};
use grin_wallet_util::OnionV3Address;
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
		false,
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
		config.owner_api_include_foreign.clone(),
		Some(tor_config.clone()),
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
pub struct SendArgs {
	pub amount: u64,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub dest: String,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
	pub payment_proof_address: Option<SlatepackAddress>,
	pub ttl_blocks: Option<u64>,
	//TODO: Remove HF3
	pub output_v4_slate: bool,
}

pub fn send<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
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
	let wallet_inst = owner_api.wallet_inst.clone();
	// Check other version, and if it only supports 3 set the target slate
	// version to 3 to avoid removing the transaction object
	// TODO: This block is temporary, for the period between the release of v4.0.0 and HF3,
	// after which this should be removable
	let mut args = args;

	//TODO: Remove block post HF3
	// All this block does is determine whether the slate should be
	// output as a V3 Slate for the receiver
	let mut tor_sender = None;
	let is_pre_fork;
	{
		is_pre_fork = {
			let cur_height = {
				libwallet::wallet_lock!(wallet_inst, w);
				w.w2n_client().get_chain_tip()?.0
			};
			match global::get_chain_type() {
				global::ChainTypes::Mainnet => {
					if cur_height < 786240 && !args.output_v4_slate {
						true
					} else {
						false
					}
				}
				global::ChainTypes::Floonet => {
					if cur_height < 552960 && !args.output_v4_slate {
						true
					} else {
						false
					}
				}
				_ => false,
			}
		};

		if is_pre_fork {
			let trailing = match args.dest.ends_with('/') {
				true => "",
				false => "/",
			};

			let mut address_found = false;
			// For sync methods, derive intended endpoint from dest
			match SlatepackAddress::try_from(args.dest.as_str()) {
				Ok(address) => {
					let tor_addr = OnionV3Address::try_from(&address).unwrap();
					// Try pinging the destination via TOR
					debug!("Version ping: TOR address is: {}", tor_addr);
					match HttpSlateSender::with_socks_proxy(
						&tor_addr.to_http_str(),
						&tor_config.as_ref().unwrap().socks_proxy_addr,
						&tor_config.as_ref().unwrap().send_config_dir,
					) {
						Ok(mut sender) => {
							let url_str =
								format!("{}{}v2/foreign", tor_addr.to_http_str(), trailing);
							if let Ok(v) = sender.check_other_version(&url_str) {
								if v == SlateVersion::V3 {
									args.target_slate_version = Some(3);
								}
								address_found = true;
							}
							tor_sender = Some(sender);
						}
						Err(e) => {
							debug!(
								"Version ping: Couldn't create slate sender for TOR: {:?}",
								e
							);
						}
					}
				}
				Err(e) => {
					debug!("Version ping: Address is not SlatepackAddress: {:?}", e);
				}
			}

			// now try http
			if !address_found {
				// Try pinging the destination via TOR
				match HttpSlateSender::new(&args.dest) {
					Ok(mut sender) => {
						let url_str = format!("{}{}v2/foreign", args.dest, trailing);
						match sender.check_other_version(&url_str) {
							Ok(v) => {
								if v == SlateVersion::V3 {
									args.target_slate_version = Some(3);
								}
								address_found = true;
							}
							Err(e) => {
								debug!(
									"Version ping: Couldn't get other version for HTTP: {:?}",
									e
								);
							}
						}
					}
					Err(e) => {
						debug!(
							"Version ping: Couldn't create slate sender for HTTP: {:?}",
							e
						);
					}
				}
			}

			if !address_found {
				// otherwise, determine slate format based on block height
				// For files spit out a V3 Slate if we're before HF3,
				// Or V4 slate otherwise
				if is_pre_fork {
					args.target_slate_version = Some(3);
				}
			}
		}
	} // end pre HF3 Block

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
				target_slate_version: args.target_slate_version,
				payment_proof_recipient_address: args.payment_proof_address.clone(),
				ttl_blocks: args.ttl_blocks,
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

			let mut send_sync =
				|mut sender: HttpSlateSender, method_str: &str| match sender.send_tx(&slate) {
					Ok(s) => {
						slate = s;
						api.tx_lock_outputs(m, &slate)?;
						slate = api.finalize_tx(m, &slate)?;
						let result = api.post_tx(m, &slate, args.fluff);
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
					Err(e) => {
						debug!(
							"Send ({}): Could not send Slate via {}: {}",
							method_str, method_str, e
						);
						return Err(e);
					}
				};

			// First, try TOR
			match SlatepackAddress::try_from(args.dest.as_str()) {
				Ok(address) => {
					let tor_addr = OnionV3Address::try_from(&address).unwrap();
					// Try sending to the destination via TOR
					let sender = match tor_sender {
						None => {
							match HttpSlateSender::with_socks_proxy(
								&tor_addr.to_http_str(),
								&tor_config.as_ref().unwrap().socks_proxy_addr,
								&tor_config.as_ref().unwrap().send_config_dir,
							) {
								Ok(s) => Some(s),
								Err(e) => {
									debug!("Send (TOR): Cannot create TOR Slate sender {:?}", e);
									None
								}
							}
						}
						Some(s) => Some(s),
					};
					if let Some(s) = sender {
						println!("Attempting to send transaction via TOR");
						match send_sync(s, "TOR") {
							Ok(_) => return Ok(()),
							Err(e) => {
								debug!("Unable to send via TOR: {}", e);
								println!("Unable to send transaction via TOR. Attempting alternate methods.");
							}
						}
					}
				}
				Err(e) => {
					debug!("Send (TOR): Destination is not SlatepackAddress {:?}", e);
				}
			}

			// Try Fallback to HTTP for deprecation period
			match HttpSlateSender::new(&args.dest) {
				Ok(sender) => {
					println!("Attempting to send transaction via HTTP (deprecated)");
					match send_sync(sender, "HTTP") {
						Ok(_) => return Ok(()),
						Err(e) => {
							debug!("Unable to send via TOR: {}", e);
							println!("Unable to send transaction via HTTP. Will output Slatepack.");
						}
					}
				}
				Err(e) => {
					debug!("Send (HTTP): Cannot create HTTP Slate sender {:?}", e);
				}
			}

			// Otherwise output slatepack
			// create a directory to which files will be output
			let slate_dir = format!("{}/{}", api.get_top_level_directory()?, "slatepack");
			let _ = std::fs::create_dir_all(slate_dir.clone());
			let out_file_name = format!("{}/{}_S1.slatepack", slate_dir, slate.id);
			// TODO: Remove HF3
			if is_pre_fork {
				PathToSlate((&out_file_name).into()).put_tx(&slate, false)?;
				api.tx_lock_outputs(m, &slate)?;
				println!("Transaction file was output to {}", out_file_name);
				println!("Please send this file to the recipient manually, and complete the transaction using the `grin-wallet finalize` command.");
				return Ok(());
			}
			// Output the slatepack file to stdout and to a file
			let address = match SlatepackAddress::try_from(args.dest.as_str()) {
				Ok(a) => Some(a),
				Err(_) => None,
			};
			// encrypt for recipient by default
			let recipients = match address.clone() {
				Some(a) => vec![a],
				None => vec![],
			};
			let message = api.create_slatepack_message(m, &slate, Some(0), recipients)?;
			let mut output = File::create(out_file_name.clone())?;
			output.write_all(&message.as_bytes())?;
			output.sync_all()?;

			api.tx_lock_outputs(m, &slate)?;

			println!();
			println!("Slatepack data follows. Please provide this output to the recipient, then finalize the result with 'grin-wallet finalize'");
			println!();
			println!("--- CUT BELOW THIS LINE ---");
			println!();
			println!("{}", message);
			println!("--- CUT ABOVE THIS LINE ---");
			println!();
			println!("Slatepack data was also output to {}", out_file_name);
			println!();
			if address.is_some() {
				println!("The slatepack data was encrypted for the recipient only");
			} else {
				println!("The slatepack data is NOT encrypted");
			}
			println!();
		}
		Ok(())
	})?;
	Ok(())
}

/// Receive command argument
pub struct ReceiveArgs {
	pub input: String,
}

pub fn receive<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (mut slate, was_bin) = PathToSlate((&args.input).into()).get_tx()?;
	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};
	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		slate = api.receive_tx(&slate, Some(&g_args.account))?;
		Ok(())
	})?;
	PathToSlate(format!("{}.response", args.input).into()).put_tx(&slate, was_bin)?;
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
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: FinalizeArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (mut slate, was_bin) = PathToSlate((&args.input).into()).get_tx()?;

	// Rather than duplicating the entire command, we'll just
	// try to determine what kind of finalization this is
	// based on the slate contents
	// for now, we can tell this is an invoice transaction
	// if the receipient (participant 1) hasn't completed sigs
	let mut is_invoice = false;
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		is_invoice = api.context_is_invoice(m, &slate)?;
		Ok(())
	})?;

	if is_invoice {
		let km = match keychain_mask.as_ref() {
			None => None,
			Some(&m) => Some(m.to_owned()),
		};
		controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
			slate = api.finalize_invoice_tx(&slate)?;
			Ok(())
		})?;
	} else {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			slate = api.finalize_tx(m, &slate)?;
			Ok(())
		})?;
	}

	if !args.nopost {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let result = api.post_tx(m, &slate, args.fluff);
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
		PathToSlate((&args.dest.unwrap()).into()).put_tx(&slate, was_bin)?;
	}

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// output file
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
	/// whether to output as bin
	pub bin: bool,
	// TODO: Remove HF3
	/// whether to output a V4 slate
	pub output_v4_slate: bool,
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
	//TODO: Remove block HF3
	let args = {
		let mut a = args;
		let wallet_inst = owner_api.wallet_inst.clone();
		let cur_height = {
			libwallet::wallet_lock!(wallet_inst, w);
			w.w2n_client().get_chain_tip()?.0
		};
		// TODO: Floonet HF4
		if cur_height < 786240 && !a.output_v4_slate && !a.bin {
			a.issue_args.target_slate_version = Some(3);
		}
		a
	};
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let slate = api.issue_invoice_tx(m, args.issue_args)?;
		PathToSlate((&args.dest).into()).put_tx(&slate, args.bin)?;
		Ok(())
	})?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub method: String,
	pub dest: String,
	pub max_outputs: usize,
	pub input: String,
	pub estimate_selection_strategies: bool,
	pub ttl_blocks: Option<u64>,
}

/// Process invoice
pub fn process_invoice<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
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
	let (slate, _) = PathToSlate((&args.input).into()).get_tx()?;
	let wallet_inst = owner_api.wallet_inst.clone();
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
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				..Default::default()
			};
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
					slate_putter.put_tx(&slate, false)?;
					api.tx_lock_outputs(m, &slate)?;
				}
				"filebin" => {
					let slate_putter = PathToSlate((&args.dest).into());
					slate_putter.put_tx(&slate, true)?;
					api.tx_lock_outputs(m, &slate)?;
				}
				"self" => {
					api.tx_lock_outputs(m, &slate)?;
					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					controller::foreign_single_use(wallet_inst, km, |api| {
						slate = api.finalize_invoice_tx(&slate)?;
						Ok(())
					})?;
				}
				method => {
					let mut sender = create_sender(method, &args.dest, tor_config)?;
					slate = sender.send_tx(&slate)?;
					api.tx_lock_outputs(m, &slate)?;
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
pub struct PostArgs {
	pub input: String,
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
	let slate = PathToSlate((&args.input).into()).get_tx()?.0;

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		api.post_tx(m, &slate, args.fluff)?;
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
		let (_, txs) = api.retrieve_txs(m, true, Some(args.id), None)?;
		let stored_tx = api.get_stored_tx(m, txs[0].tx_slate_id.unwrap())?;
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
				let mut slate = Slate::blank(2, false);
				slate.tx = Some(stored_tx.unwrap());
				api.post_tx(m, &slate, args.fluff)?;
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
