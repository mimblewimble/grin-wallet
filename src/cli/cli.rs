// Copyright 2020 The Grin Developers
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

use crate::cmd::wallet_args;
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use clap::App;
//use colored::Colorize;
use grin_wallet_api::Owner;
use grin_wallet_config::{TorConfig, WalletConfig};
use grin_wallet_controller::command::GlobalArgs;
use grin_wallet_controller::Error;
use grin_wallet_impls::DefaultWalletImpl;
use grin_wallet_libwallet::{NodeClient, StatusMessage, WalletInst, WalletLCProvider};
use grin_wallet_util::grin_keychain as keychain;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, EditMode, Editor, Helper, OutputStreamType};
use std::borrow::Cow::{self, Borrowed, Owned};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const COLORED_PROMPT: &'static str = "\x1b[36mgrin-wallet>\x1b[0m ";
const PROMPT: &'static str = "grin-wallet> ";
//const HISTORY_PATH: &str = ".history";

// static for keeping track of current stdin buffer contents
lazy_static! {
	static ref STDIN_CONTENTS: Mutex<String> = { Mutex::new(String::from("")) };
}

#[macro_export]
macro_rules! cli_message_inline {
	($fmt_string:expr, $( $arg:expr ),+) => {
			{
					use std::io::Write;
					let contents = STDIN_CONTENTS.lock();
					/* use crate::common::{is_cli, COLORED_PROMPT}; */
					/* if is_cli() { */
							print!("\r");
							print!($fmt_string, $( $arg ),*);
							print!(" {}", COLORED_PROMPT);
							print!("\x1B[J");
							print!("{}", *contents);
							std::io::stdout().flush().unwrap();
					/*} else {
							info!($fmt_string, $( $arg ),*);
					}*/
			}
	};
}

#[macro_export]
macro_rules! cli_message {
	($fmt_string:expr, $( $arg:expr ),+) => {
			{
					use std::io::Write;
					/* use crate::common::{is_cli, COLORED_PROMPT}; */
					/* if is_cli() { */
							//print!("\r");
							print!($fmt_string, $( $arg ),*);
							println!();
							std::io::stdout().flush().unwrap();
					/*} else {
							info!($fmt_string, $( $arg ),*);
					}*/
			}
	};
}

/// function to catch updates
pub fn start_updater_thread(rx: Receiver<StatusMessage>) -> Result<(), Error> {
	let _ = thread::Builder::new()
		.name("wallet-updater-status".to_string())
		.spawn(move || loop {
			while let Ok(m) = rx.recv() {
				match m {
					StatusMessage::UpdatingOutputs(s) => cli_message_inline!("{}", s),
					StatusMessage::UpdatingTransactions(s) => cli_message_inline!("{}", s),
					StatusMessage::FullScanWarn(s) => cli_message_inline!("{}", s),
					StatusMessage::Scanning(_, m) => {
						//debug!("{}", s);
						cli_message_inline!("Scanning - {}% complete - Please Wait", m);
					}
					StatusMessage::ScanningComplete(s) => cli_message_inline!("{}", s),
					StatusMessage::UpdateWarning(s) => cli_message_inline!("{}", s),
				}
			}
		});
	Ok(())
}

pub fn command_loop<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<SecretKey>,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	global_wallet_args: &GlobalArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let editor = Config::builder()
		.history_ignore_space(true)
		.completion_type(CompletionType::List)
		.edit_mode(EditMode::Emacs)
		.output_stream(OutputStreamType::Stdout)
		.build();

	let mut reader = Editor::with_config(editor);
	reader.set_helper(Some(EditorHelper(
		FilenameCompleter::new(),
		MatchingBracketHighlighter::new(),
	)));

	/*let history_file = self
		.api
		.config()
		.get_data_path()
		.unwrap()
		.parent()
		.unwrap()
		.join(HISTORY_PATH);
	if history_file.exists() {
		let _ = reader.load_history(&history_file);
	}*/

	let yml = load_yaml!("../bin/grin-wallet.yml");
	let mut app = App::from_yaml(yml).version(crate_version!());
	let mut keychain_mask = keychain_mask;

	// catch updater messages
	let (tx, rx) = channel();
	let mut owner_api = Owner::new(wallet_inst, Some(tx));
	start_updater_thread(rx)?;

	// start the automatic updater
	owner_api.start_updater((&keychain_mask).as_ref(), Duration::from_secs(30))?;
	let mut wallet_opened = false;
	loop {
		match reader.readline(PROMPT) {
			Ok(command) => {
				if command.is_empty() {
					continue;
				}
				// TODO tidy up a bit
				if command.to_lowercase() == "exit" {
					break;
				}
				/* use crate::common::{is_cli, COLORED_PROMPT}; */

				// reset buffer
				{
					let mut contents = STDIN_CONTENTS.lock();
					*contents = String::from("");
				}

				// Just add 'grin-wallet' to each command behind the scenes
				// so we don't need to maintain a separate definition file
				let augmented_command = format!("grin-wallet {}", command);
				let args =
					app.get_matches_from_safe_borrow(augmented_command.trim().split_whitespace());
				let done = match args {
					Ok(args) => {
						// handle opening /closing separately
						keychain_mask = match args.subcommand() {
							("open", Some(_)) => {
								let mut wallet_lock = owner_api.wallet_inst.lock();
								let lc = wallet_lock.lc_provider().unwrap();
								let mask = match lc.open_wallet(
									None,
									wallet_args::prompt_password(&global_wallet_args.password),
									false,
									false,
								) {
									Ok(m) => {
										wallet_opened = true;
										m
									}
									Err(e) => {
										cli_message!("{}", e);
										None
									}
								};
								if let Some(account) = args.value_of("account") {
									if wallet_opened {
										let wallet_inst = lc.wallet_inst()?;
										wallet_inst.set_parent_key_id_by_name(account)?;
									}
								}
								mask
							}
							("close", Some(_)) => {
								let mut wallet_lock = owner_api.wallet_inst.lock();
								let lc = wallet_lock.lc_provider().unwrap();
								lc.close_wallet(None)?;
								None
							}
							_ => keychain_mask,
						};
						match wallet_args::parse_and_execute(
							&mut owner_api,
							keychain_mask.clone(),
							&wallet_config,
							&tor_config,
							&global_wallet_args,
							&args,
							test_mode,
							true,
						) {
							Ok(_) => {
								cli_message!("Command '{}' completed", args.subcommand().0);
								false
							}
							Err(err) => {
								cli_message!("{}", err);
								false
							}
						}
					}
					Err(err) => {
						cli_message!("{}", err);
						false
					}
				};
				reader.add_history_entry(command);
				if done {
					println!();
					break;
				}
			}
			Err(err) => {
				println!("Unable to read line: {}", err);
				break;
			}
		}
	}
	Ok(())

	//let _ = reader.save_history(&history_file);
}

struct EditorHelper(FilenameCompleter, MatchingBracketHighlighter);

impl Completer for EditorHelper {
	type Candidate = Pair;

	fn complete(
		&self,
		line: &str,
		pos: usize,
		ctx: &Context<'_>,
	) -> std::result::Result<(usize, Vec<Pair>), ReadlineError> {
		self.0.complete(line, pos, ctx)
	}
}

impl Hinter for EditorHelper {
	fn hint(&self, line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
		let mut contents = STDIN_CONTENTS.lock();
		*contents = line.into();
		None
	}
}

impl Highlighter for EditorHelper {
	fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
		self.1.highlight(line, pos)
	}

	fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
		&'s self,
		prompt: &'p str,
		default: bool,
	) -> Cow<'b, str> {
		if default {
			Borrowed(COLORED_PROMPT)
		} else {
			Borrowed(prompt)
		}
	}

	fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
		Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
	}

	fn highlight_char(&self, line: &str, pos: usize) -> bool {
		self.1.highlight_char(line, pos)
	}
}
impl Validator for EditorHelper {}
impl Helper for EditorHelper {}
