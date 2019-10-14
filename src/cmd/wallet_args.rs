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

use crate::api::TLSConfig;
use crate::config::GRIN_WALLET_DIR;
use crate::util::file::get_first_line;
use crate::util::{Mutex, ZeroingString};
/// Argument parsing and error handling for wallet commands
use clap::ArgMatches;
use failure::Fail;
use grin_wallet_config::{TorConfig, WalletConfig};
use grin_wallet_controller::command;
use grin_wallet_controller::{Error, ErrorKind};
use grin_wallet_impls::tor::config::is_tor_address;
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use grin_wallet_impls::{PathToSlate, SlateGetter as _};
use grin_wallet_libwallet::Slate;
use grin_wallet_libwallet::{IssueInvoiceTxArgs, NodeClient, WalletInst, WalletLCProvider};
use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_core::core::amount_to_hr_string;
use grin_wallet_util::grin_core::global;
use grin_wallet_util::grin_keychain as keychain;
use linefeed::terminal::Signal;
use linefeed::{Interface, ReadResult};
use rpassword;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// define what to do on argument error
macro_rules! arg_parse {
	( $r:expr ) => {
		match $r {
			Ok(res) => res,
			Err(e) => {
				return Err(ErrorKind::ArgumentError(format!("{}", e)).into());
				}
			}
	};
}
/// Simple error definition, just so we can return errors from all commands
/// and let the caller figure out what to do
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ParseError {
	#[fail(display = "Invalid Arguments: {}", _0)]
	ArgumentError(String),
	#[fail(display = "Parsing IO error: {}", _0)]
	IOError(String),
	#[fail(display = "User Cancelled")]
	CancelledError,
}

impl From<std::io::Error> for ParseError {
	fn from(e: std::io::Error) -> ParseError {
		ParseError::IOError(format!("{}", e))
	}
}

fn prompt_password_stdout(prompt: &str) -> ZeroingString {
	ZeroingString::from(rpassword::prompt_password_stdout(prompt).unwrap())
}

pub fn prompt_password(password: &Option<ZeroingString>) -> ZeroingString {
	match password {
		None => prompt_password_stdout("Password: "),
		Some(p) => p.clone(),
	}
}

fn prompt_password_confirm() -> ZeroingString {
	let mut first = ZeroingString::from("first");
	let mut second = ZeroingString::from("second");
	while first != second {
		first = prompt_password_stdout("Password: ");
		second = prompt_password_stdout("Confirm Password: ");
	}
	first
}

fn prompt_replace_seed() -> Result<bool, ParseError> {
	let interface = Arc::new(Interface::new("replace_seed")?);
	interface.set_report_signal(Signal::Interrupt, true);
	interface.set_prompt("Replace seed? (y/n)> ")?;
	println!();
	println!("Existing wallet.seed file already exists. Continue?");
	println!("Continuing will back up your existing 'wallet.seed' file as 'wallet.seed.bak'");
	println!();
	loop {
		let res = interface.read_line()?;
		match res {
			ReadResult::Eof => return Ok(false),
			ReadResult::Signal(sig) => {
				if sig == Signal::Interrupt {
					interface.cancel_read_line()?;
					return Err(ParseError::CancelledError);
				}
			}
			ReadResult::Input(line) => match line.trim() {
				"Y" | "y" => return Ok(true),
				"N" | "n" => return Ok(false),
				_ => println!("Please respond y or n"),
			},
		}
	}
}

fn prompt_recovery_phrase<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
) -> Result<ZeroingString, ParseError>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let interface = Arc::new(Interface::new("recover")?);
	let mut phrase = ZeroingString::from("");
	interface.set_report_signal(Signal::Interrupt, true);
	interface.set_prompt("phrase> ")?;
	loop {
		println!("Please enter your recovery phrase:");
		let res = interface.read_line()?;
		match res {
			ReadResult::Eof => break,
			ReadResult::Signal(sig) => {
				if sig == Signal::Interrupt {
					interface.cancel_read_line()?;
					return Err(ParseError::CancelledError);
				}
			}
			ReadResult::Input(line) => {
				let mut w_lock = wallet.lock();
				let p = w_lock.lc_provider().unwrap();
				if p.validate_mnemonic(ZeroingString::from(line.clone()))
					.is_ok()
				{
					phrase = ZeroingString::from(line);
					break;
				} else {
					println!();
					println!("Recovery word phrase is invalid.");
					println!();
					interface.set_buffer(&line)?;
				}
			}
		}
	}
	Ok(phrase)
}

fn prompt_pay_invoice(slate: &Slate, method: &str, dest: &str) -> Result<bool, ParseError> {
	let interface = Arc::new(Interface::new("pay")?);
	let amount = amount_to_hr_string(slate.amount, false);
	interface.set_report_signal(Signal::Interrupt, true);
	interface.set_prompt(
		"To proceed, type the exact amount of the invoice as displayed above (or Q/q to quit) > ",
	)?;
	println!();
	println!(
		"This command will pay the amount specified in the invoice using your wallet's funds."
	);
	println!("After you confirm, the following will occur: ");
	println!();
	println!(
		"* {} of your wallet funds will be added to the transaction to pay this invoice.",
		amount
	);
	if method == "http" {
		println!("* The resulting transaction will IMMEDIATELY be sent to the wallet listening at: '{}'.", dest);
	} else {
		println!("* The resulting transaction will be saved to the file '{}', which you can manually send back to the invoice creator.", dest);
	}
	println!();
	println!("The invoice slate's participant info is:");
	for m in slate.participant_messages().messages {
		println!("{}", m);
	}
	println!("Please review the above information carefully before proceeding");
	println!();
	loop {
		let res = interface.read_line()?;
		match res {
			ReadResult::Eof => return Ok(false),
			ReadResult::Signal(sig) => {
				if sig == Signal::Interrupt {
					interface.cancel_read_line()?;
					return Err(ParseError::CancelledError);
				}
			}
			ReadResult::Input(line) => {
				match line.trim() {
					"Q" | "q" => return Err(ParseError::CancelledError),
					result => {
						if result == amount {
							return Ok(true);
						} else {
							println!("Please enter exact amount of the invoice as shown above or Q to quit");
							println!();
						}
					}
				}
			}
		}
	}
}

// instantiate wallet (needed by most functions)

pub fn inst_wallet<L, C, K>(
	config: WalletConfig,
	node_client: C,
) -> Result<Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>, ParseError>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut wallet = Box::new(DefaultWalletImpl::<'static, C>::new(node_client.clone()).unwrap())
		as Box<dyn WalletInst<'static, L, C, K>>;
	let lc = wallet.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&config.data_file_dir);
	Ok(Arc::new(Mutex::new(wallet)))
}

// parses a required value, or throws error with message otherwise
fn parse_required<'a>(args: &'a ArgMatches, name: &str) -> Result<&'a str, ParseError> {
	let arg = args.value_of(name);
	match arg {
		Some(ar) => Ok(ar),
		None => {
			let msg = format!("Value for argument '{}' is required in this context", name,);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

// parses a number, or throws error with message otherwise
fn parse_u64(arg: &str, name: &str) -> Result<u64, ParseError> {
	let val = arg.parse::<u64>();
	match val {
		Ok(v) => Ok(v),
		Err(e) => {
			let msg = format!("Could not parse {} as a whole number. e={}", name, e);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

pub fn parse_global_args(
	config: &WalletConfig,
	args: &ArgMatches,
) -> Result<command::GlobalArgs, ParseError> {
	let account = parse_required(args, "account")?;
	let mut show_spent = false;
	if args.is_present("show_spent") {
		show_spent = true;
	}
	let api_secret = get_first_line(config.api_secret_path.clone());
	let node_api_secret = get_first_line(config.node_api_secret_path.clone());
	let password = match args.value_of("pass") {
		None => None,
		Some(p) => Some(ZeroingString::from(p)),
	};

	let tls_conf = match config.tls_certificate_file.clone() {
		None => None,
		Some(file) => {
			let key = match config.tls_certificate_key.clone() {
				Some(k) => k,
				None => {
					let msg = format!("Private key for certificate is not set");
					return Err(ParseError::ArgumentError(msg));
				}
			};
			Some(TLSConfig::new(file, key))
		}
	};

	let chain_type = match config.chain_type.clone() {
		None => {
			let param_ref = global::CHAIN_TYPE.read();
			param_ref.clone()
		}
		Some(c) => c,
	};

	Ok(command::GlobalArgs {
		account: account.to_owned(),
		show_spent: show_spent,
		chain_type: chain_type,
		api_secret: api_secret,
		node_api_secret: node_api_secret,
		password: password,
		tls_conf: tls_conf,
	})
}

pub fn parse_init_args<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	config: &WalletConfig,
	g_args: &command::GlobalArgs,
	args: &ArgMatches,
) -> Result<command::InitArgs, ParseError>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let list_length = match args.is_present("short_wordlist") {
		false => 32,
		true => 16,
	};
	let recovery_phrase = match args.is_present("recover") {
		true => Some(prompt_recovery_phrase(wallet)?),
		false => None,
	};

	if recovery_phrase.is_some() {
		println!("Please provide a new password for the recovered wallet");
	} else {
		println!("Please enter a password for your new wallet");
	}

	let password = match g_args.password.clone() {
		Some(p) => p,
		None => prompt_password_confirm(),
	};

	Ok(command::InitArgs {
		list_length: list_length,
		password: password,
		config: config.clone(),
		recovery_phrase: recovery_phrase,
		restore: false,
	})
}

pub fn parse_recover_args<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	g_args: &command::GlobalArgs,
	args: &ArgMatches,
) -> Result<command::RecoverArgs, ParseError>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (passphrase, recovery_phrase) = {
		match args.is_present("display") {
			true => (prompt_password(&g_args.password), None),
			false => {
				let cont = {
					let mut w_lock = wallet.lock();
					let p = w_lock.lc_provider().unwrap();
					if p.wallet_exists(None).unwrap() {
						prompt_replace_seed()?
					} else {
						true
					}
				};
				if !cont {
					return Err(ParseError::CancelledError);
				}
				let phrase = prompt_recovery_phrase(wallet.clone())?;
				println!("Please provide a new password for the recovered wallet");
				(prompt_password_confirm(), Some(phrase.to_owned()))
			}
		}
	};
	Ok(command::RecoverArgs {
		passphrase: passphrase,
		recovery_phrase: recovery_phrase,
	})
}

pub fn parse_listen_args(
	config: &mut WalletConfig,
	tor_config: &mut TorConfig,
	args: &ArgMatches,
) -> Result<command::ListenArgs, ParseError> {
	if let Some(port) = args.value_of("port") {
		config.api_listen_port = port.parse().unwrap();
	}
	let method = parse_required(args, "method")?;
	if args.is_present("no_tor") {
		tor_config.use_tor_listener = false;
	}
	Ok(command::ListenArgs {
		method: method.to_owned(),
	})
}

pub fn parse_owner_api_args(
	config: &mut WalletConfig,
	args: &ArgMatches,
) -> Result<(), ParseError> {
	if let Some(port) = args.value_of("port") {
		config.owner_api_listen_port = Some(port.parse().unwrap());
	}
	if args.is_present("run_foreign") {
		config.owner_api_include_foreign = Some(true);
	}
	Ok(())
}

pub fn parse_account_args(account_args: &ArgMatches) -> Result<command::AccountArgs, ParseError> {
	let create = match account_args.value_of("create") {
		None => None,
		Some(s) => Some(s.to_owned()),
	};
	Ok(command::AccountArgs { create: create })
}

pub fn parse_send_args(args: &ArgMatches) -> Result<command::SendArgs, ParseError> {
	// amount
	let amount = parse_required(args, "amount")?;
	let amount = core::core::amount_from_hr_string(amount);
	let amount = match amount {
		Ok(a) => a,
		Err(e) => {
			let msg = format!(
				"Could not parse amount as a number with optional decimal point. e={}",
				e
			);
			return Err(ParseError::ArgumentError(msg));
		}
	};

	// message
	let message = match args.is_present("message") {
		true => Some(args.value_of("message").unwrap().to_owned()),
		false => None,
	};

	// minimum_confirmations
	let min_c = parse_required(args, "minimum_confirmations")?;
	let min_c = parse_u64(min_c, "minimum_confirmations")?;

	// selection_strategy
	let selection_strategy = parse_required(args, "selection_strategy")?;

	// estimate_selection_strategies
	let estimate_selection_strategies = args.is_present("estimate_selection_strategies");

	// method
	let method = parse_required(args, "method")?;

	// dest
	let dest = {
		if method == "self" {
			match args.value_of("dest") {
				Some(d) => d,
				None => "default",
			}
		} else {
			if !estimate_selection_strategies {
				parse_required(args, "dest")?
			} else {
				""
			}
		}
	};

	if !estimate_selection_strategies
		&& method == "http"
		&& !dest.starts_with("http://")
		&& !dest.starts_with("https://")
		&& is_tor_address(&dest).is_err()
	{
		let msg = format!(
			"HTTP Destination should start with http://: or https://: {}",
			dest,
		);
		return Err(ParseError::ArgumentError(msg));
	}

	// change_outputs
	let change_outputs = parse_required(args, "change_outputs")?;
	let change_outputs = parse_u64(change_outputs, "change_outputs")? as usize;

	// fluff
	let fluff = args.is_present("fluff");

	// max_outputs
	let max_outputs = 500;

	// target slate version to create/send
	let target_slate_version = {
		match args.is_present("slate_version") {
			true => {
				let v = parse_required(args, "slate_version")?;
				Some(parse_u64(v, "slate_version")? as u16)
			}
			false => None,
		}
	};

	Ok(command::SendArgs {
		amount: amount,
		message: message,
		minimum_confirmations: min_c,
		selection_strategy: selection_strategy.to_owned(),
		estimate_selection_strategies,
		method: method.to_owned(),
		dest: dest.to_owned(),
		change_outputs: change_outputs,
		fluff: fluff,
		max_outputs: max_outputs,
		target_slate_version: target_slate_version,
	})
}

pub fn parse_receive_args(receive_args: &ArgMatches) -> Result<command::ReceiveArgs, ParseError> {
	// message
	let message = match receive_args.is_present("message") {
		true => Some(receive_args.value_of("message").unwrap().to_owned()),
		false => None,
	};

	// input
	let tx_file = parse_required(receive_args, "input")?;

	// validate input
	if !Path::new(&tx_file).is_file() {
		let msg = format!("File {} not found.", &tx_file);
		return Err(ParseError::ArgumentError(msg));
	}

	Ok(command::ReceiveArgs {
		input: tx_file.to_owned(),
		message: message,
	})
}

pub fn parse_finalize_args(args: &ArgMatches) -> Result<command::FinalizeArgs, ParseError> {
	let fluff = args.is_present("fluff");
	let tx_file = parse_required(args, "input")?;

	if !Path::new(&tx_file).is_file() {
		let msg = format!("File {} not found.", tx_file);
		return Err(ParseError::ArgumentError(msg));
	}
	Ok(command::FinalizeArgs {
		input: tx_file.to_owned(),
		fluff: fluff,
	})
}

pub fn parse_issue_invoice_args(
	args: &ArgMatches,
) -> Result<command::IssueInvoiceArgs, ParseError> {
	let amount = parse_required(args, "amount")?;
	let amount = core::core::amount_from_hr_string(amount);
	let amount = match amount {
		Ok(a) => a,
		Err(e) => {
			let msg = format!(
				"Could not parse amount as a number with optional decimal point. e={}",
				e
			);
			return Err(ParseError::ArgumentError(msg));
		}
	};
	// message
	let message = match args.is_present("message") {
		true => Some(args.value_of("message").unwrap().to_owned()),
		false => None,
	};
	// target slate version to create
	let target_slate_version = {
		match args.is_present("slate_version") {
			true => {
				let v = parse_required(args, "slate_version")?;
				Some(parse_u64(v, "slate_version")? as u16)
			}
			false => None,
		}
	};
	// dest (output file)
	let dest = parse_required(args, "dest")?;
	Ok(command::IssueInvoiceArgs {
		dest: dest.into(),
		issue_args: IssueInvoiceTxArgs {
			dest_acct_name: None,
			amount,
			message,
			target_slate_version,
		},
	})
}

pub fn parse_process_invoice_args(
	args: &ArgMatches,
	prompt: bool,
) -> Result<command::ProcessInvoiceArgs, ParseError> {
	// TODO: display and prompt for confirmation of what we're doing
	// message
	let message = match args.is_present("message") {
		true => Some(args.value_of("message").unwrap().to_owned()),
		false => None,
	};

	// minimum_confirmations
	let min_c = parse_required(args, "minimum_confirmations")?;
	let min_c = parse_u64(min_c, "minimum_confirmations")?;

	// selection_strategy
	let selection_strategy = parse_required(args, "selection_strategy")?;

	// estimate_selection_strategies
	let estimate_selection_strategies = args.is_present("estimate_selection_strategies");

	// method
	let method = parse_required(args, "method")?;

	// dest
	let dest = {
		if method == "self" {
			match args.value_of("dest") {
				Some(d) => d,
				None => "default",
			}
		} else {
			if !estimate_selection_strategies {
				parse_required(args, "dest")?
			} else {
				""
			}
		}
	};
	if !estimate_selection_strategies
		&& method == "http"
		&& !dest.starts_with("http://")
		&& !dest.starts_with("https://")
	{
		let msg = format!(
			"HTTP Destination should start with http://: or https://: {}",
			dest,
		);
		return Err(ParseError::ArgumentError(msg));
	}

	// max_outputs
	let max_outputs = 500;

	// file input only
	let tx_file = parse_required(args, "input")?;

	if prompt {
		// Now we need to prompt the user whether they want to do this,
		// which requires reading the slate

		let slate = match PathToSlate((&tx_file).into()).get_tx() {
			Ok(s) => s,
			Err(e) => return Err(ParseError::ArgumentError(format!("{}", e))),
		};

		prompt_pay_invoice(&slate, method, dest)?;
	}

	Ok(command::ProcessInvoiceArgs {
		message: message,
		minimum_confirmations: min_c,
		selection_strategy: selection_strategy.to_owned(),
		estimate_selection_strategies,
		method: method.to_owned(),
		dest: dest.to_owned(),
		max_outputs: max_outputs,
		input: tx_file.to_owned(),
	})
}

pub fn parse_info_args(args: &ArgMatches) -> Result<command::InfoArgs, ParseError> {
	// minimum_confirmations
	let mc = parse_required(args, "minimum_confirmations")?;
	let mc = parse_u64(mc, "minimum_confirmations")?;
	Ok(command::InfoArgs {
		minimum_confirmations: mc,
	})
}

pub fn parse_check_args(args: &ArgMatches) -> Result<command::CheckArgs, ParseError> {
	let delete_unconfirmed = args.is_present("delete_unconfirmed");
	Ok(command::CheckArgs {
		delete_unconfirmed: delete_unconfirmed,
	})
}

pub fn parse_txs_args(args: &ArgMatches) -> Result<command::TxsArgs, ParseError> {
	let tx_id = match args.value_of("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};
	let tx_slate_id = match args.value_of("txid") {
		None => None,
		Some(tx) => match tx.parse() {
			Ok(t) => Some(t),
			Err(e) => {
				let msg = format!("Could not parse txid parameter. e={}", e);
				return Err(ParseError::ArgumentError(msg));
			}
		},
	};
	if tx_id.is_some() && tx_slate_id.is_some() {
		let msg = format!("At most one of 'id' (-i) or 'txid' (-t) may be provided.");
		return Err(ParseError::ArgumentError(msg));
	}
	Ok(command::TxsArgs {
		id: tx_id,
		tx_slate_id: tx_slate_id,
	})
}

pub fn parse_repost_args(args: &ArgMatches) -> Result<command::RepostArgs, ParseError> {
	let tx_id = match args.value_of("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};

	let fluff = args.is_present("fluff");
	let dump_file = match args.value_of("dumpfile") {
		None => None,
		Some(d) => Some(d.to_owned()),
	};

	Ok(command::RepostArgs {
		id: tx_id.unwrap(),
		dump_file: dump_file,
		fluff: fluff,
	})
}

pub fn parse_cancel_args(args: &ArgMatches) -> Result<command::CancelArgs, ParseError> {
	let mut tx_id_string = "";
	let tx_id = match args.value_of("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};
	let tx_slate_id = match args.value_of("txid") {
		None => None,
		Some(tx) => match tx.parse() {
			Ok(t) => {
				tx_id_string = tx;
				Some(t)
			}
			Err(e) => {
				let msg = format!("Could not parse txid parameter. e={}", e);
				return Err(ParseError::ArgumentError(msg));
			}
		},
	};
	if (tx_id.is_none() && tx_slate_id.is_none()) || (tx_id.is_some() && tx_slate_id.is_some()) {
		let msg = format!("'id' (-i) or 'txid' (-t) argument is required.");
		return Err(ParseError::ArgumentError(msg));
	}
	Ok(command::CancelArgs {
		tx_id: tx_id,
		tx_slate_id: tx_slate_id,
		tx_id_string: tx_id_string.to_owned(),
	})
}

pub fn wallet_command<C, F>(
	wallet_args: &ArgMatches,
	mut wallet_config: WalletConfig,
	tor_config: Option<TorConfig>,
	mut node_client: C,
	test_mode: bool,
	wallet_inst_cb: F,
) -> Result<String, Error>
where
	C: NodeClient + 'static + Clone,
	F: FnOnce(
		Arc<
			Mutex<
				Box<
					dyn WalletInst<
						'static,
						DefaultLCProvider<'static, C, keychain::ExtKeychain>,
						C,
						keychain::ExtKeychain,
					>,
				>,
			>,
		>,
	),
{
	if let Some(t) = wallet_config.chain_type.clone() {
		core::global::set_mining_mode(t);
	}

	if wallet_args.is_present("external") {
		wallet_config.api_listen_interface = "0.0.0.0".to_string();
	}

	if let Some(dir) = wallet_args.value_of("data_dir") {
		wallet_config.data_file_dir = dir.to_string().clone();
	}

	if let Some(sa) = wallet_args.value_of("api_server_address") {
		wallet_config.check_node_api_http_addr = sa.to_string().clone();
	}

	let global_wallet_args = arg_parse!(parse_global_args(&wallet_config, &wallet_args));

	node_client.set_node_url(&wallet_config.check_node_api_http_addr);
	node_client.set_node_api_secret(global_wallet_args.node_api_secret.clone());

	// legacy hack to avoid the need for changes in existing grin-wallet.toml files
	// remove `wallet_data` from end of path as
	// new lifecycle provider assumes grin_wallet.toml is in root of data directory
	let mut top_level_wallet_dir = PathBuf::from(wallet_config.clone().data_file_dir);
	if top_level_wallet_dir.ends_with(GRIN_WALLET_DIR) {
		top_level_wallet_dir.pop();
		wallet_config.data_file_dir = top_level_wallet_dir.to_str().unwrap().into();
	}

	// for backwards compatibility: If tor config doesn't exist in the file, assume
	// the top level directory for data
	let tor_config = match tor_config {
		Some(tc) => tc,
		None => {
			let mut tc = TorConfig::default();
			tc.send_config_dir = wallet_config.data_file_dir.clone();
			tc
		}
	};

	// Instantiate wallet (doesn't open the wallet)
	let wallet =
		inst_wallet::<DefaultLCProvider<C, keychain::ExtKeychain>, C, keychain::ExtKeychain>(
			wallet_config.clone(),
			node_client,
		)
		.unwrap_or_else(|e| {
			println!("{}", e);
			std::process::exit(1);
		});

	{
		let mut wallet_lock = wallet.lock();
		let lc = wallet_lock.lc_provider().unwrap();
		let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
	}

	// provide wallet instance back to the caller (handy for testing with
	// local wallet proxy, etc)
	wallet_inst_cb(wallet.clone());

	// don't open wallet for certain lifecycle commands
	let mut open_wallet = true;
	match wallet_args.subcommand() {
		("init", Some(_)) => open_wallet = false,
		("recover", _) => open_wallet = false,
		("owner_api", _) => {
			// If wallet exists, open it. Otherwise, that's fine too.
			let mut wallet_lock = wallet.lock();
			let lc = wallet_lock.lc_provider().unwrap();
			open_wallet = lc.wallet_exists(None)?;
		}
		_ => {}
	}

	let keychain_mask = match open_wallet {
		true => {
			let mut wallet_lock = wallet.lock();
			let lc = wallet_lock.lc_provider().unwrap();
			let mask = lc.open_wallet(
				None,
				prompt_password(&global_wallet_args.password),
				false,
				false,
			)?;
			if let Some(account) = wallet_args.value_of("account") {
				let wallet_inst = lc.wallet_inst()?;
				wallet_inst.set_parent_key_id_by_name(account)?;
			}
			mask
		}
		false => None,
	};

	let km = (&keychain_mask).as_ref();

	let res = match wallet_args.subcommand() {
		("init", Some(args)) => {
			let a = arg_parse!(parse_init_args(
				wallet.clone(),
				&wallet_config,
				&global_wallet_args,
				&args
			));
			command::init(wallet, &global_wallet_args, a)
		}
		("recover", Some(args)) => {
			let a = arg_parse!(parse_recover_args(
				wallet.clone(),
				&global_wallet_args,
				&args
			));
			command::recover(wallet, a)
		}
		("listen", Some(args)) => {
			let mut c = wallet_config.clone();
			let mut t = tor_config.clone();
			let a = arg_parse!(parse_listen_args(&mut c, &mut t, &args));
			command::listen(
				wallet,
				Arc::new(Mutex::new(keychain_mask)),
				&c,
				&t,
				&a,
				&global_wallet_args.clone(),
			)
		}
		("owner_api", Some(args)) => {
			let mut c = wallet_config.clone();
			let mut g = global_wallet_args.clone();
			g.tls_conf = None;
			arg_parse!(parse_owner_api_args(&mut c, &args));
			command::owner_api(wallet, keychain_mask, &c, &g)
		}
		("web", Some(_)) => {
			command::owner_api(wallet, keychain_mask, &wallet_config, &global_wallet_args)
		}
		("account", Some(args)) => {
			let a = arg_parse!(parse_account_args(&args));
			command::account(wallet, km, a)
		}
		("send", Some(args)) => {
			let a = arg_parse!(parse_send_args(&args));
			command::send(
				wallet,
				km,
				Some(tor_config),
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("receive", Some(args)) => {
			let a = arg_parse!(parse_receive_args(&args));
			command::receive(wallet, km, &global_wallet_args, a)
		}
		("finalize", Some(args)) => {
			let a = arg_parse!(parse_finalize_args(&args));
			command::finalize(wallet, km, a)
		}
		("invoice", Some(args)) => {
			let a = arg_parse!(parse_issue_invoice_args(&args));
			command::issue_invoice_tx(wallet, km, a)
		}
		("pay", Some(args)) => {
			let a = arg_parse!(parse_process_invoice_args(&args, !test_mode));
			command::process_invoice(
				wallet,
				km,
				Some(tor_config),
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("info", Some(args)) => {
			let a = arg_parse!(parse_info_args(&args));
			command::info(
				wallet,
				km,
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("outputs", Some(_)) => command::outputs(
			wallet,
			km,
			&global_wallet_args,
			wallet_config.dark_background_color_scheme.unwrap_or(true),
		),
		("txs", Some(args)) => {
			let a = arg_parse!(parse_txs_args(&args));
			command::txs(
				wallet,
				km,
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("repost", Some(args)) => {
			let a = arg_parse!(parse_repost_args(&args));
			command::repost(wallet, km, a)
		}
		("cancel", Some(args)) => {
			let a = arg_parse!(parse_cancel_args(&args));
			command::cancel(wallet, km, a)
		}
		("restore", Some(_)) => command::restore(wallet, km),
		("check", Some(args)) => {
			let a = arg_parse!(parse_check_args(&args));
			command::check_repair(wallet, km, a)
		}
		_ => {
			let msg = format!("Unknown wallet command, use 'grin-wallet help' for details");
			return Err(ErrorKind::ArgumentError(msg).into());
		}
	};
	if let Err(e) = res {
		Err(e)
	} else {
		Ok(wallet_args.subcommand().0.to_owned())
	}
}
