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

//! Terminal driver for the wallet TUI.
//!
//! Most wallet operations run on worker threads (`worker.rs`) so Tor
//! round-trips, chain scans and node timeouts never freeze the interface.
//! Dashboard data arrives from a background refresher. Open/close/recover
//! still run on the UI thread via in-TUI password modals (they need the
//! interactive password prompt and update local lifecycle state). The only
//! place the normal terminal is used is first-run wallet creation, before
//! the dashboard opens.

use crate::cmd::wallet_args;
use crate::tui::actions::{self, FormState};
use crate::tui::app::{App, Dialog, Focus, SharedState, Tab};
use crate::tui::form::TextField;
use crate::tui::modals::{
	ConfirmPayState, ContextAction, ContextMenuState, EditSettingState, Modal, OutputState,
	PasswordPurpose, PasswordState, SlatepackInputState,
};
use crate::tui::worker::{
	self, OpResult, PayParams, RefreshCtrl, SendParams, SlateInput, SlateOpParams, UiMsg, WorkerCtx,
};
use crate::tui::{accounts, logs as logs_view, menu, modals, outputs, settings, status, txs};
use clap::App as ClapApp;
use crossterm::event::{
	self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
	Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
	disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use grin_keychain as keychain;
use grin_util::logger::LogEntry;
use grin_util::secp::key::SecretKey;
use grin_util::{to_base64, Mutex, ZeroingString};
use grin_wallet_api::Owner;
use grin_wallet_config::{TorConfig, WalletConfig, WALLET_CONFIG_FILE_NAME};
use grin_wallet_controller::command::GlobalArgs;
use grin_wallet_controller::Error;
use grin_wallet_impls::DefaultWalletImpl;
use grin_wallet_libwallet::{
	NodeClient, SlatepackArmor, StatusMessage, WalletInst, WalletLCProvider,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{self, Stdout, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

type Backend = CrosstermBackend<Stdout>;

/// Redraw at least this often even without input or new data.
const MAX_REDRAW_INTERVAL: Duration = Duration::from_millis(250);
/// How far PageUp/PageDown move a table selection
const TABLE_PAGE_SIZE: i64 = 10;

fn install_panic_hook() {
	let original_hook = std::panic::take_hook();
	std::panic::set_hook(Box::new(move |panic_info| {
		let _ = disable_raw_mode();
		let _ = execute!(
			io::stdout(),
			LeaveAlternateScreen,
			DisableMouseCapture,
			DisableBracketedPaste
		);
		original_hook(panic_info);
	}));
}

fn prompt_yes_no(question: &str, default_yes: bool) -> bool {
	let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
	print!("{} {} ", question, hint);
	let _ = io::stdout().flush();
	let mut line = String::new();
	if io::stdin().read_line(&mut line).is_err() {
		return default_yes;
	}
	let line = line.trim();
	if line.is_empty() {
		default_yes
	} else {
		matches!(line.to_lowercase().as_str(), "y" | "yes")
	}
}

fn status_message_to_log(msg: StatusMessage) -> LogEntry {
	let text = match msg {
		StatusMessage::UpdatingOutputs(s) => s,
		StatusMessage::UpdatingTransactions(s) => s,
		StatusMessage::FullScanWarn(s) => s,
		StatusMessage::Scanning(s, pct) => format!("{} ({}%)", s, pct),
		StatusMessage::ScanningComplete(s) => s,
		StatusMessage::UpdateWarning(s) => s,
	};
	LogEntry {
		log: text,
		level: log::Level::Info,
	}
}

/// Copy text to the terminal's clipboard via the OSC 52 escape sequence
/// (supported by most modern terminal emulators, no dependency needed).
fn copy_to_clipboard(text: &str) {
	let mut out = io::stdout();
	let _ = write!(out, "\x1b]52;c;{}\x07", to_base64(text));
	let _ = out.flush();
}

/// Parse `argv` as a `grin-wallet` command line and execute it through the
/// CLI dispatch. Only used *before* the dashboard opens (first-run `init`
/// and the initial unlock) when a normal terminal is still available.
fn run_subcommand<L, C, K>(
	argv: Vec<String>,
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: &mut Option<SecretKey>,
	locked: &mut bool,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	global_wallet_args: &GlobalArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	DefaultWalletImpl<C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let yml = load_yaml!("../bin/grin-wallet.yml");
	let clap_app = ClapApp::from_yaml(yml).version(crate_version!());
	let matches = match clap_app.get_matches_from_safe(argv) {
		Ok(m) => m,
		Err(e) => {
			println!("{}", e);
			return Ok(());
		}
	};

	match matches.subcommand() {
		("open", Some(_)) => {
			let password = match wallet_args::prompt_password(&global_wallet_args.password) {
				Ok(p) => p,
				Err(e) => {
					println!("Failed to read password: {}", e);
					return Ok(());
				}
			};
			match owner_api.open_wallet(None, password, false) {
				Ok(mask) => {
					let _ =
						owner_api.set_active_account(mask.as_ref(), &global_wallet_args.account);
					*keychain_mask = mask;
					*locked = false;
					println!("Wallet unlocked.");
				}
				Err(e) => println!("Failed to open wallet: {}", e),
			}
			Ok(())
		}
		_ => wallet_args::parse_and_execute(
			owner_api,
			keychain_mask.clone(),
			wallet_config,
			tor_config.clone(),
			global_wallet_args,
			&matches,
			test_mode,
			true,
		),
	}
}

fn draw_dialog(f: &mut Frame, area: Rect, dialog: &Dialog) {
	let popup_area = modals::centered_rect(60, 20, area);
	let block = Block::default()
		.borders(Borders::ALL)
		.title("Notice (press any key to dismiss)");
	let paragraph = Paragraph::new(dialog.text.clone())
		.style(Style::default().fg(Color::Yellow))
		.block(block)
		.wrap(Wrap { trim: false });
	f.render_widget(Clear, popup_area);
	f.render_widget(paragraph, popup_area);
}

fn draw_frame(
	f: &mut Frame,
	app: &mut App,
	config_path: &str,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	shared: &SharedState,
) {
	let size = f.area();
	let outer = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(size);

	let mut title = format!(
		"Grin Wallet TUI - Account: {}{}",
		app.view.account,
		if app.locked { " (locked)" } else { "" }
	);
	if let Some(op) = shared.busy_with() {
		title.push_str(&format!("  [working: {} ...]", op));
	}
	let title_widget = Paragraph::new(title)
		.style(Style::default().fg(Color::Green))
		.block(Block::default().borders(Borders::ALL));
	f.render_widget(title_widget, outer[0]);

	let body = Layout::horizontal([Constraint::Length(24), Constraint::Min(0)]).split(outer[1]);

	menu::draw(f, body[0], app);

	let content_block = Block::default().borders(Borders::ALL);
	let content_area = content_block.inner(body[1]);
	f.render_widget(content_block, body[1]);

	match app.tab {
		Tab::Status => status::draw(f, content_area, app, shared),
		Tab::Accounts => accounts::draw(f, content_area, app),
		Tab::Outputs => outputs::draw(f, content_area, app),
		Tab::Transactions => txs::draw(f, content_area, app),
		Tab::Actions => actions::draw(f, content_area, &mut app.actions_list),
		Tab::Settings => settings::draw(
			f,
			content_area,
			&app.settings_list,
			config_path,
			wallet_config,
			tor_config,
			shared,
		),
		Tab::Logs => logs_view::draw(f, content_area, app),
	}

	if let Some(modal) = &mut app.modal {
		modals::draw(f, size, modal);
	}

	if let Some(dialog) = &app.dialog {
		draw_dialog(f, size, dialog);
	}
}

struct Controller<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	terminal: Terminal<Backend>,
	app: App,
	owner_api: Owner<L, C, K>,
	keychain_mask: Option<SecretKey>,
	wallet_config: WalletConfig,
	tor_config: TorConfig,
	global_wallet_args: GlobalArgs,
	shared: Arc<SharedState>,
	ctx: WorkerCtx<L, C, K>,
	config_path: String,
	logs_rx: Option<mpsc::Receiver<LogEntry>>,
	status_rx: mpsc::Receiver<StatusMessage>,
	ui_rx: mpsc::Receiver<UiMsg>,
	refresh_tx: mpsc::Sender<RefreshCtrl>,
	needs_redraw: bool,
	last_draw: Instant,
}

impl<L, C, K> Controller<L, C, K>
where
	DefaultWalletImpl<C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	fn request_refresh(&self) {
		let _ = self.refresh_tx.send(RefreshCtrl::Now);
	}

	fn on_down(&mut self) {
		match self.app.focus {
			Focus::Menu => self.app.select_menu_next(),
			Focus::Content => match self.app.tab {
				Tab::Actions => {
					Self::move_list(&mut self.app.actions_list, actions::ACTIONS.len(), 1)
				}
				Tab::Settings => {
					Self::move_list(&mut self.app.settings_list, settings::SETTINGS.len(), 1)
				}
				_ => self.move_table_selection(1),
			},
		}
	}

	fn on_up(&mut self) {
		match self.app.focus {
			Focus::Menu => self.app.select_menu_prev(),
			Focus::Content => match self.app.tab {
				Tab::Actions => {
					Self::move_list(&mut self.app.actions_list, actions::ACTIONS.len(), -1)
				}
				Tab::Settings => {
					Self::move_list(&mut self.app.settings_list, settings::SETTINGS.len(), -1)
				}
				_ => self.move_table_selection(-1),
			},
		}
	}

	fn move_list(state: &mut ratatui::widgets::ListState, len: usize, delta: i64) {
		if len == 0 {
			return;
		}
		let current = state.selected().unwrap_or(0) as i64;
		let next = (current + delta).rem_euclid(len as i64);
		state.select(Some(next as usize));
	}

	fn move_table_selection(&mut self, delta: i64) {
		let len = self.app.current_table_len();
		let state = match self.app.tab {
			Tab::Accounts => Some(&mut self.app.accounts_table),
			Tab::Outputs => Some(&mut self.app.outputs_table),
			Tab::Transactions => Some(&mut self.app.txs_table),
			_ => None,
		};
		if let Some(state) = state {
			if len == 0 {
				state.select(None);
				return;
			}
			let current = state.selected().unwrap_or(0) as i64;
			let next = current.saturating_add(delta).clamp(0, len as i64 - 1);
			state.select(Some(next as usize));
		}
	}

	/// Enter pressed while the content pane is focused
	fn on_content_enter(&mut self) {
		match self.app.tab {
			Tab::Actions => {
				if let Some(idx) = self.app.actions_list.selected() {
					self.app.modal = Some(Modal::Form(FormState::new(idx)));
				}
			}
			Tab::Transactions => {
				if let Some(row) = self.app.txs_table.selected() {
					if let Some(tx) = self.app.view.txs.get(row) {
						let id = tx.id.to_string();
						let mut items = vec![
							(
								format!("Cancel transaction {}", id),
								ContextAction::OpenForm {
									spec_idx: actions::action_index("cancel").unwrap(),
									prefill: vec![("id", id.clone())],
								},
							),
							(
								format!("Repost transaction {}", id),
								ContextAction::OpenForm {
									spec_idx: actions::action_index("repost").unwrap(),
									prefill: vec![("id", id.clone())],
								},
							),
							(
								format!("Export payment proof for {}", id),
								ContextAction::OpenForm {
									spec_idx: actions::action_index("export_proof").unwrap(),
									prefill: vec![("id", id.clone())],
								},
							),
						];
						if let Some(slate_id) = tx.tx_slate_id {
							items.push((
								format!("Copy slate ID {}", slate_id),
								ContextAction::Copy(slate_id.to_string()),
							));
						}
						self.app.modal = Some(Modal::Context(ContextMenuState {
							title: format!("Transaction {}", id),
							items,
							selected: 0,
						}));
					}
				}
			}
			Tab::Accounts => {
				if let Some(row) = self.app.accounts_table.selected() {
					if let Some(acct) = self.app.view.accounts.get(row) {
						let label = acct.label.clone();
						if label == *self.shared.account.lock() {
							self.app.dialog = Some(Dialog {
								text: format!("'{}' is already the active account.", label),
							});
						} else {
							self.app.modal = Some(Modal::Context(ContextMenuState {
								title: format!("Account '{}'", label),
								items: vec![(
									format!("Switch active account to '{}'", label),
									ContextAction::SwitchAccount(label),
								)],
								selected: 0,
							}));
						}
					}
				}
			}
			Tab::Settings => {
				if let Some(idx) = self.app.settings_list.selected() {
					// Prefill from global config when available so multi-wallet
					// / Owner-API updates are visible in the editor.
					let (wallet, tor) = settings::effective_configs(
						std::path::Path::new(&self.config_path),
						&self.wallet_config,
						&self.tor_config,
					);
					let current = settings::current_value(
						settings::SETTINGS[idx].kind,
						&wallet,
						&tor,
						&self.shared,
					);
					self.app.modal = Some(Modal::EditSetting(EditSettingState {
						setting_idx: idx,
						field: TextField::new(&current),
						error: None,
					}));
				}
			}
			_ => {}
		}
	}

	/// Block lifecycle actions (and quit) while a worker is mid-operation.
	fn refuse_if_busy(&mut self, action: &str) -> bool {
		if let Some(op) = self.shared.busy_with() {
			self.app.dialog = Some(Dialog {
				text: format!(
					"Cannot {} while '{}' is still in progress. Wait for it to finish.",
					action, op
				),
			});
			true
		} else {
			false
		}
	}

	fn switch_account(&mut self, label: String) {
		if self.refuse_if_busy("switch account") {
			return;
		}
		let mask = self.keychain_mask.clone();
		match self.owner_api.set_active_account(mask.as_ref(), &label) {
			Ok(_) => {
				*self.shared.account.lock() = label.clone();
				self.global_wallet_args.account = label.clone();
				self.app.view.account = label.clone();
				self.app.dialog = Some(Dialog {
					text: format!("Active account switched to '{}'.", label),
				});
				self.request_refresh();
			}
			Err(e) => {
				self.app.dialog = Some(Dialog {
					text: format!("Could not switch account: {}", e),
				});
			}
		}
	}

	/// Start an open/unlock: reuse CLI `-p` password once if provided, else
	/// open the masked password modal. The long-lived CLI password copy is
	/// cleared after the first use so it is not retained for the session.
	fn begin_open(&mut self) {
		if !self.app.locked {
			self.app.dialog = Some(Dialog {
				text: "Wallet is already unlocked.".to_string(),
			});
			return;
		}
		if self.refuse_if_busy("open the wallet") {
			return;
		}
		if let Some(p) = self.global_wallet_args.password.take() {
			match self.open_with_password(p) {
				Ok(()) => {
					self.app.dialog = Some(Dialog {
						text: "Wallet unlocked.".to_string(),
					});
					self.request_refresh();
				}
				Err(e) => {
					self.app.dialog = Some(Dialog {
						text: format!("Failed to open wallet: {}", e),
					});
				}
			}
			return;
		}
		self.app.modal = Some(Modal::Password(PasswordState::new(PasswordPurpose::Open)));
	}

	fn begin_recover(&mut self) {
		if self.refuse_if_busy("recover the phrase") {
			return;
		}
		if let Some(p) = self.global_wallet_args.password.take() {
			match self.recover_with_password(p) {
				Ok(body) => {
					// Never put the recovery phrase on the clipboard path.
					self.app.modal = Some(Modal::Output(OutputState::from_text(
						"Recovery Phrase".to_string(),
						body,
						None,
					)));
				}
				Err(e) => {
					self.app.dialog = Some(Dialog {
						text: format!("Failed to recover phrase: {}", e),
					});
				}
			}
			return;
		}
		self.app.modal.replace(Modal::Password(PasswordState::new(
			PasswordPurpose::Recover,
		)));
	}

	/// Returns Ok on success. Caller is responsible for UI feedback.
	fn open_with_password(&mut self, password: ZeroingString) -> Result<(), String> {
		match self.owner_api.open_wallet(None, password, false) {
			Ok(mask) => {
				let _ = self
					.owner_api
					.set_active_account(mask.as_ref(), &self.global_wallet_args.account);
				self.keychain_mask = mask.clone();
				*self.shared.mask.lock() = mask;
				self.shared.locked.store(false, Ordering::Relaxed);
				self.app.locked = false;
				// Drop any leftover CLI password after a successful unlock.
				self.global_wallet_args.password = None;
				Ok(())
			}
			Err(e) => Err(format!("{}", e)),
		}
	}

	/// Display body only — recovery phrases are never offered for clipboard copy.
	fn recover_with_password(&mut self, password: ZeroingString) -> Result<String, String> {
		let mut w_lock = self.owner_api.wallet_inst.lock();
		let p = w_lock.lc_provider().map_err(|e| format!("{}", e))?;
		let phrase = p
			.get_mnemonic(None, password)
			.map_err(|e| format!("{}", e))?;
		// Keep phrase in ZeroingString until we format the one-shot display body.
		let body = format!(
			"Your recovery phrase is:\n\n{}\n\nPlease back-up these words in a non-digital format.\n\nClipboard copy is disabled for recovery phrases.",
			&*phrase
		);
		// `phrase` drops here and zeroes its allocation.
		Ok(body)
	}

	fn do_close(&mut self) {
		if self.app.locked {
			self.app.dialog = Some(Dialog {
				text: "Wallet is already locked.".to_string(),
			});
			return;
		}
		if self.refuse_if_busy("close the wallet") {
			return;
		}
		match self.owner_api.close_wallet(None) {
			Ok(()) => {
				self.keychain_mask = None;
				*self.shared.mask.lock() = None;
				self.shared.locked.store(true, Ordering::Relaxed);
				self.app.locked = true;
				self.app.dialog = Some(Dialog {
					text: "Wallet locked.".to_string(),
				});
				self.request_refresh();
			}
			Err(e) => {
				self.app.dialog = Some(Dialog {
					text: format!("Failed to close wallet: {}", e),
				});
			}
		}
	}

	/// Route a validated, submitted form to its executor
	fn submit_form(&mut self, form: FormState) {
		let spec = form.spec();
		// open/close/recover never leave the alternate screen
		match spec.subcommand {
			"open" => {
				self.begin_open();
				return;
			}
			"close" => {
				self.do_close();
				return;
			}
			"recover" => {
				self.begin_recover();
				return;
			}
			_ => {}
		}
		if self.app.locked {
			self.app.dialog = Some(Dialog {
				text: "The wallet is locked - use Actions > Open first.".to_string(),
			});
			return;
		}
		match spec.subcommand {
			"send" => {
				let p = SendParams {
					amount: form.positional(0),
					dest: form.text("dest"),
					min_conf: form.u64_opt("min_conf").unwrap_or(10),
					strategy_all: form.flag("selection_all"),
					change_outputs: form.u32_opt("change_outputs").unwrap_or(1),
					ttl_blocks: form.u64_opt("ttl_blocks"),
					fluff: form.flag("fluff"),
					no_payment_proof: form.flag("no_payment_proof"),
					manual: form.flag("manual"),
					amount_includes_fee: form.flag("amount_includes_fee"),
					estimate: form.flag("estimate"),
					outfile: form.text_opt("outfile"),
				};
				worker::spawn_send(&self.ctx, p);
			}
			"receive" => self.slate_op(
				&form,
				"Receive",
				SlateOpParams::Receive {
					manual: form.flag("manual"),
					outfile: form.text_opt("outfile"),
				},
			),
			"finalize" => self.slate_op(
				&form,
				"Finalize",
				SlateOpParams::Finalize {
					fluff: form.flag("fluff"),
					nopost: form.flag("nopost"),
					outfile: form.text_opt("outfile"),
				},
			),
			"post" => self.slate_op(
				&form,
				"Post",
				SlateOpParams::Post {
					fluff: form.flag("fluff"),
				},
			),
			"unpack" => self.slate_op(&form, "Unpack", SlateOpParams::Unpack),
			"pay" => self.slate_op(
				&form,
				"Pay Invoice",
				SlateOpParams::PayParse(PayParams {
					dest_override: form.text_opt("dest"),
					min_conf: form.u64_opt("min_conf").unwrap_or(10),
					strategy_all: form.flag("selection_all"),
					ttl_blocks: form.u64_opt("ttl_blocks"),
					manual: form.flag("manual"),
					outfile: form.text_opt("outfile"),
				}),
			),
			"invoice" => worker::spawn_invoice(
				&self.ctx,
				form.positional(0),
				form.text("dest"),
				form.text_opt("outfile"),
			),
			"repost" => worker::spawn_repost(
				&self.ctx,
				form.u32_opt("id").unwrap_or(0),
				form.text_opt("dumpfile"),
				form.flag("fluff"),
			),
			"cancel" => worker::spawn_cancel(
				&self.ctx,
				form.u32_opt("id"),
				form.text_opt("txid").and_then(|s| Uuid::parse_str(&s).ok()),
			),
			"account" => worker::spawn_account_create(&self.ctx, form.text("create")),
			"export_proof" => worker::spawn_proof_export(
				&self.ctx,
				form.positional(0),
				form.u32_opt("id"),
				form.text_opt("txid").and_then(|s| Uuid::parse_str(&s).ok()),
			),
			"verify_proof" => worker::spawn_proof_verify(&self.ctx, form.positional(0)),
			"address" => worker::spawn_address(&self.ctx),
			"rewind_hash" => worker::spawn_rewind_hash(&self.ctx),
			"scan" => worker::spawn_scan(
				&self.ctx,
				form.u64_opt("start_height"),
				form.u64_opt("backwards_from_tip"),
				form.flag("delete_unconfirmed"),
			),
			"scan_rewind_hash" => worker::spawn_scan_rewind_hash(
				&self.ctx,
				form.positional(0),
				form.u64_opt("start_height"),
				form.u64_opt("backwards_from_tip"),
			),
			"listen" => worker::spawn_listener(
				&self.ctx,
				form.u16_opt("port"),
				form.flag("no_tor"),
				form.text_opt("bridge"),
			),
			"owner_api" => {
				worker::spawn_owner_api(&self.ctx, form.u16_opt("port"), form.flag("run_foreign"))
			}
			other => {
				self.app.dialog = Some(Dialog {
					text: format!("'{}' is not implemented in the TUI yet.", other),
				});
			}
		}
	}

	/// Dispatch a slate-consuming op: use the input file if given,
	/// otherwise open the paste modal.
	fn slate_op(&mut self, form: &FormState, title: &str, op: SlateOpParams) {
		let input = form.text("input");
		if input.is_empty() {
			self.app.modal = Some(Modal::SlatepackInput(SlatepackInputState {
				title: title.to_string(),
				buffer: String::new(),
				error: None,
				op,
			}));
		} else {
			worker::spawn_slate_op(&self.ctx, SlateInput::File(input), op);
		}
	}

	/// A background operation finished
	fn handle_op_result(&mut self, res: OpResult) {
		self.request_refresh();
		match res {
			OpResult::Slatepack {
				title,
				lines,
				armored,
				qr,
			} => {
				self.app.modal = Some(Modal::Output(OutputState {
					title,
					lines,
					copy: Some(armored),
					qr,
					show_qr: false,
					scroll: 0,
				}));
			}
			OpResult::Text { title, body, copy } => {
				self.app.modal = Some(Modal::Output(OutputState::from_text(title, body, copy)));
			}
			OpResult::Info(text) => {
				self.app.dialog = Some(Dialog { text });
			}
			OpResult::Error(text) => {
				self.app.dialog = Some(Dialog {
					text: format!("Error: {}", text),
				});
			}
			OpResult::ConfirmPay {
				amount,
				dest,
				params,
				slate,
			} => {
				self.app.modal = Some(Modal::ConfirmPay(ConfirmPayState {
					amount,
					dest,
					params,
					slate,
				}));
			}
		}
	}

	fn handle_modal_key(&mut self, code: KeyCode) {
		// Take the modal out to avoid borrowing self mutably twice;
		// handlers put it back unless the interaction finished.
		let modal = match self.app.modal.take() {
			Some(m) => m,
			None => return,
		};
		match modal {
			Modal::Form(mut form) => match code {
				KeyCode::Esc => {}
				KeyCode::Tab | KeyCode::Down => {
					form.next_field();
					self.app.modal = Some(Modal::Form(form));
				}
				KeyCode::BackTab | KeyCode::Up => {
					form.prev_field();
					self.app.modal = Some(Modal::Form(form));
				}
				KeyCode::Enter => {
					if form.focused_is_bool() {
						form.toggle_focused();
						self.app.modal = Some(Modal::Form(form));
					} else if form.field_count() > 0 && form.focus + 1 < form.field_count() {
						form.next_field();
						self.app.modal = Some(Modal::Form(form));
					} else {
						match form.validate() {
							Ok(()) => self.submit_form(form),
							Err(e) => {
								form.error = Some(e);
								self.app.modal = Some(Modal::Form(form));
							}
						}
					}
				}
				KeyCode::Char(' ') if form.focused_is_bool() => {
					form.toggle_focused();
					self.app.modal = Some(Modal::Form(form));
				}
				code => {
					if let Some(t) = form.focused_text() {
						match code {
							KeyCode::Left => t.left(),
							KeyCode::Right => t.right(),
							KeyCode::Home => t.home(),
							KeyCode::End => t.end(),
							KeyCode::Backspace => t.backspace(),
							KeyCode::Delete => t.delete(),
							KeyCode::Char(c) => t.insert(c),
							_ => {}
						}
					}
					self.app.modal = Some(Modal::Form(form));
				}
			},
			Modal::SlatepackInput(mut state) => match code {
				KeyCode::Esc => {}
				KeyCode::Enter => {
					let message = state.buffer.trim().to_string();
					if SlatepackArmor::decode(message.as_bytes()).is_ok() {
						worker::spawn_slate_op(&self.ctx, SlateInput::Message(message), state.op);
					} else {
						state.error = Some("Input is not a valid slatepack.".to_string());
						self.app.modal = Some(Modal::SlatepackInput(state));
					}
				}
				KeyCode::Backspace => {
					state.buffer.pop();
					self.app.modal = Some(Modal::SlatepackInput(state));
				}
				KeyCode::Char(c) => {
					state.buffer.push(c);
					self.app.modal = Some(Modal::SlatepackInput(state));
				}
				_ => {
					self.app.modal = Some(Modal::SlatepackInput(state));
				}
			},
			Modal::Output(mut state) => match code {
				KeyCode::Esc | KeyCode::Enter => {}
				KeyCode::Up | KeyCode::Char('k') => {
					state.scroll = state.scroll.saturating_sub(1);
					self.app.modal = Some(Modal::Output(state));
				}
				KeyCode::Down | KeyCode::Char('j') => {
					state.scroll = state.scroll.saturating_add(1);
					self.app.modal = Some(Modal::Output(state));
				}
				KeyCode::PageUp => {
					state.scroll = state.scroll.saturating_sub(TABLE_PAGE_SIZE as u16);
					self.app.modal = Some(Modal::Output(state));
				}
				KeyCode::PageDown => {
					state.scroll = state.scroll.saturating_add(TABLE_PAGE_SIZE as u16);
					self.app.modal = Some(Modal::Output(state));
				}
				KeyCode::Char('q') => {
					if state.qr.is_some() {
						state.show_qr = !state.show_qr;
						state.scroll = 0;
					}
					self.app.modal = Some(Modal::Output(state));
				}
				KeyCode::Char('c') => {
					if let Some(text) = &state.copy {
						copy_to_clipboard(text);
						self.app.dialog = Some(Dialog {
							text: "Copied to clipboard.".to_string(),
						});
					}
					self.app.modal = Some(Modal::Output(state));
				}
				_ => {
					self.app.modal = Some(Modal::Output(state));
				}
			},
			Modal::ConfirmPay(state) => match code {
				KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
					let dest = state.dest.clone();
					worker::spawn_pay_process(&self.ctx, state.slate, dest, state.params);
				}
				KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('q') => {}
				_ => {
					self.app.modal = Some(Modal::ConfirmPay(state));
				}
			},
			Modal::Context(mut state) => match code {
				KeyCode::Esc => {}
				KeyCode::Up | KeyCode::Char('k') => {
					state.prev();
					self.app.modal = Some(Modal::Context(state));
				}
				KeyCode::Down | KeyCode::Char('j') => {
					state.next();
					self.app.modal = Some(Modal::Context(state));
				}
				KeyCode::Enter => {
					if let Some((_, action)) = state.items.into_iter().nth(state.selected) {
						match action {
							ContextAction::OpenForm { spec_idx, prefill } => {
								let mut form = FormState::new(spec_idx);
								for (name, value) in prefill {
									form = form.prefill(name, &value);
								}
								self.app.modal = Some(Modal::Form(form));
							}
							ContextAction::SwitchAccount(label) => self.switch_account(label),
							ContextAction::Copy(text) => {
								copy_to_clipboard(&text);
								self.app.dialog = Some(Dialog {
									text: "Copied to clipboard.".to_string(),
								});
							}
						}
					}
				}
				_ => {
					self.app.modal = Some(Modal::Context(state));
				}
			},
			Modal::Password(mut state) => match code {
				KeyCode::Esc => {}
				KeyCode::Enter => {
					if state.field.value.is_empty() {
						state.error = Some("Password cannot be empty".to_string());
						self.app.modal = Some(Modal::Password(state));
						return;
					}
					let password = ZeroingString::from(state.field.value.clone());
					// Zero the plaintext field before we keep the modal on error.
					state.field.clear_secure();
					state.field = TextField::new_password();
					match state.purpose {
						PasswordPurpose::Open => match self.open_with_password(password) {
							Ok(()) => {
								self.app.dialog = Some(Dialog {
									text: "Wallet unlocked.".to_string(),
								});
								self.request_refresh();
							}
							Err(e) => {
								state.error = Some(format!("Failed to open wallet: {}", e));
								self.app.modal = Some(Modal::Password(state));
							}
						},
						PasswordPurpose::Recover => match self.recover_with_password(password) {
							Ok(body) => {
								self.app.modal = Some(Modal::Output(OutputState::from_text(
									"Recovery Phrase".to_string(),
									body,
									None,
								)));
							}
							Err(e) => {
								state.error = Some(format!("Failed to recover phrase: {}", e));
								self.app.modal = Some(Modal::Password(state));
							}
						},
					}
				}
				KeyCode::Left => {
					state.field.left();
					self.app.modal = Some(Modal::Password(state));
				}
				KeyCode::Right => {
					state.field.right();
					self.app.modal = Some(Modal::Password(state));
				}
				KeyCode::Home => {
					state.field.home();
					self.app.modal = Some(Modal::Password(state));
				}
				KeyCode::End => {
					state.field.end();
					self.app.modal = Some(Modal::Password(state));
				}
				KeyCode::Backspace => {
					state.field.backspace();
					self.app.modal = Some(Modal::Password(state));
				}
				KeyCode::Delete => {
					state.field.delete();
					self.app.modal = Some(Modal::Password(state));
				}
				KeyCode::Char(c) => {
					state.field.insert(c);
					self.app.modal = Some(Modal::Password(state));
				}
				_ => {
					self.app.modal = Some(Modal::Password(state));
				}
			},
			Modal::EditSetting(mut state) => match code {
				KeyCode::Esc => {}
				KeyCode::Enter => {
					let setting = &settings::SETTINGS[state.setting_idx];
					match settings::apply(
						setting,
						&state.field.value,
						&self.config_path,
						&mut self.wallet_config,
						&mut self.tor_config,
						&self.shared,
					) {
						Ok(notice) => {
							// keep the worker context in sync with the
							// edited configuration
							self.ctx.wallet_config = self.wallet_config.clone();
							self.ctx.tor_config = self.tor_config.clone();
							self.app.dialog = Some(Dialog { text: notice });
							self.request_refresh();
						}
						Err(e) => {
							state.error = Some(e);
							self.app.modal = Some(Modal::EditSetting(state));
						}
					}
				}
				KeyCode::Left => {
					state.field.left();
					self.app.modal = Some(Modal::EditSetting(state));
				}
				KeyCode::Right => {
					state.field.right();
					self.app.modal = Some(Modal::EditSetting(state));
				}
				KeyCode::Home => {
					state.field.home();
					self.app.modal = Some(Modal::EditSetting(state));
				}
				KeyCode::End => {
					state.field.end();
					self.app.modal = Some(Modal::EditSetting(state));
				}
				KeyCode::Backspace => {
					state.field.backspace();
					self.app.modal = Some(Modal::EditSetting(state));
				}
				KeyCode::Delete => {
					state.field.delete();
					self.app.modal = Some(Modal::EditSetting(state));
				}
				KeyCode::Char(c) => {
					state.field.insert(c);
					self.app.modal = Some(Modal::EditSetting(state));
				}
				_ => {
					self.app.modal = Some(Modal::EditSetting(state));
				}
			},
			Modal::Help => {}
		}
	}

	fn handle_paste(&mut self, data: String) {
		match &mut self.app.modal {
			Some(Modal::SlatepackInput(state)) => {
				state.buffer.push_str(&data);
			}
			Some(Modal::Form(form)) => {
				if let Some(t) = form.focused_text() {
					t.paste(&data);
				}
			}
			Some(Modal::EditSetting(state)) => {
				state.field.paste(&data);
			}
			Some(Modal::Password(state)) => {
				state.field.paste(&data);
			}
			_ => {}
		}
	}

	fn handle_key(&mut self, code: KeyCode) {
		if self.app.dialog.is_some() {
			self.app.dialog = None;
			return;
		}
		if self.app.modal.is_some() {
			self.handle_modal_key(code);
			return;
		}

		match code {
			KeyCode::Char('q') | KeyCode::Char('Q') => {
				if !self.refuse_if_busy("quit") {
					self.app.should_quit = true;
				}
			}
			KeyCode::Char('?') => self.app.modal = Some(Modal::Help),
			KeyCode::Char('j') | KeyCode::Down => self.on_down(),
			KeyCode::Char('k') | KeyCode::Up => self.on_up(),
			KeyCode::PageDown => self.move_table_selection(TABLE_PAGE_SIZE),
			KeyCode::PageUp => self.move_table_selection(-TABLE_PAGE_SIZE),
			KeyCode::Home => self.move_table_selection(i64::MIN),
			KeyCode::End => self.move_table_selection(i64::MAX),
			KeyCode::Tab => self.app.select_menu_next(),
			KeyCode::Char('s') => {
				self.app.show_spent = !self.app.show_spent;
				self.shared
					.show_spent
					.store(self.app.show_spent, Ordering::Relaxed);
				self.request_refresh();
			}
			KeyCode::Char('c') if self.app.tab == Tab::Status => {
				if let Some(addr) = &self.app.view.address {
					copy_to_clipboard(addr);
					self.app.dialog = Some(Dialog {
						text: "Slatepack address copied to clipboard.".to_string(),
					});
				}
			}
			KeyCode::Enter => {
				if self.app.focus == Focus::Menu {
					self.app.focus = Focus::Content;
				} else {
					self.on_content_enter();
				}
			}
			KeyCode::Esc => self.app.focus = Focus::Menu,
			_ => {}
		}
	}

	fn handle_mouse(&mut self, kind: MouseEventKind, column: u16, row: u16) {
		if self.app.modal.is_some() || self.app.dialog.is_some() {
			return;
		}
		match kind {
			MouseEventKind::Down(MouseButton::Left) => {
				let pos = Position { x: column, y: row };
				if self.app.menu_area.contains(pos) {
					let idx = (row - self.app.menu_area.y) as usize;
					if idx < Tab::ALL.len() {
						self.app.tab = Tab::ALL[idx];
						self.app.focus = Focus::Menu;
					}
				}
			}
			MouseEventKind::ScrollDown => self.on_down(),
			MouseEventKind::ScrollUp => self.on_up(),
			_ => {}
		}
	}

	fn draw(&mut self) {
		let app = &mut self.app;
		let config_path = self.config_path.as_str();
		let wallet_config = &self.wallet_config;
		let tor_config = &self.tor_config;
		let shared = &self.shared;
		let _ = self
			.terminal
			.draw(|f| draw_frame(f, app, config_path, wallet_config, tor_config, shared));
	}

	/// Step the UI once. Returns `false` when it's time to quit.
	fn step(&mut self) -> bool {
		if self.app.should_quit {
			return false;
		}

		if let Some(logs_rx) = &self.logs_rx {
			while let Some(entry) = logs_rx.try_iter().next() {
				self.app.push_log(entry);
				self.needs_redraw = true;
			}
		}
		while let Some(msg) = self.status_rx.try_iter().next() {
			self.app.push_log(status_message_to_log(msg));
			self.needs_redraw = true;
		}
		while let Ok(msg) = self.ui_rx.try_recv() {
			match msg {
				UiMsg::View(view) => {
					self.app.view = *view;
					self.app.locked = self.shared.is_locked();
				}
				UiMsg::Op(res) => self.handle_op_result(res),
			}
			self.needs_redraw = true;
		}

		if event::poll(Duration::from_millis(50)).unwrap_or(false) {
			match event::read() {
				Ok(Event::Key(key)) => {
					if key.kind == KeyEventKind::Press {
						self.handle_key(key.code);
						self.needs_redraw = true;
					}
				}
				Ok(Event::Mouse(mouse)) => {
					self.handle_mouse(mouse.kind, mouse.column, mouse.row);
					self.needs_redraw = true;
				}
				Ok(Event::Paste(data)) => {
					self.handle_paste(data);
					self.needs_redraw = true;
				}
				Ok(Event::Resize(_, _)) => self.needs_redraw = true,
				_ => {}
			}
		}

		if self.app.should_quit {
			return false;
		}

		if self.needs_redraw || self.last_draw.elapsed() >= MAX_REDRAW_INTERVAL {
			self.draw();
			self.needs_redraw = false;
			self.last_draw = Instant::now();
		}
		true
	}

	fn teardown(&mut self) {
		let _ = disable_raw_mode();
		let _ = execute!(
			self.terminal.backend_mut(),
			LeaveAlternateScreen,
			DisableMouseCapture,
			DisableBracketedPaste
		);
		let _ = self.terminal.show_cursor();
	}
}

impl<L, C, K> Drop for Controller<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	fn drop(&mut self) {
		let _ = disable_raw_mode();
		let _ = execute!(
			self.terminal.backend_mut(),
			LeaveAlternateScreen,
			DisableMouseCapture,
			DisableBracketedPaste
		);
	}
}

/// Run the interactive wallet TUI: a long-lived process holding an open
/// wallet across many commands, presented as a full-screen dashboard.
pub fn run<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	global_wallet_args: &GlobalArgs,
	test_mode: bool,
	logs_rx: Option<mpsc::Receiver<LogEntry>>,
	config_file_path: PathBuf,
) -> Result<(), Error>
where
	DefaultWalletImpl<C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (status_tx, status_rx) = mpsc::channel::<StatusMessage>();
	let (ui_tx, ui_rx) = mpsc::channel::<UiMsg>();
	let mut owner_api = Owner::new(
		wallet_inst,
		Some(status_tx.clone()),
		config_file_path.clone(),
	);
	let mut keychain_mask: Option<SecretKey> = None;
	let mut locked = true;
	// Local copy so we can drop the CLI password after the initial unlock.
	let mut global_args = global_wallet_args.clone();

	let wallet_exists = {
		let mut w_lock = owner_api.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.wallet_exists(None)?
	};

	if !wallet_exists {
		println!("No wallet found in this directory.");
		if prompt_yes_no("Create a new wallet now?", true) {
			let recover = prompt_yes_no("Restore from an existing recovery phrase?", false);
			let mut argv = vec!["grin-wallet".to_string(), "init".to_string()];
			if recover {
				argv.push("-r".to_string());
			}
			if let Err(e) = run_subcommand(
				argv,
				&mut owner_api,
				&mut keychain_mask,
				&mut locked,
				wallet_config,
				tor_config,
				&global_args,
				test_mode,
			) {
				println!("Failed to create wallet: {}", e);
				return Ok(());
			}
		} else {
			println!("Run 'grin-wallet init' when you're ready to create a wallet.");
			return Ok(());
		}
	}

	if let Err(e) = run_subcommand(
		vec!["grin-wallet".to_string(), "open".to_string()],
		&mut owner_api,
		&mut keychain_mask,
		&mut locked,
		wallet_config,
		tor_config,
		&global_args,
		test_mode,
	) {
		println!("Failed to open wallet: {}", e);
		return Ok(());
	}
	if locked {
		println!("Could not open wallet, exiting.");
		return Ok(());
	}
	// Do not retain the CLI `--pass` copy for the rest of the TUI session.
	global_args.password = None;

	let _ = owner_api.start_updater(keychain_mask.as_ref(), Duration::from_secs(30));

	let shared = Arc::new(SharedState::new(
		global_args.account.clone(),
		owner_api.updater_running.clone(),
	));
	*shared.mask.lock() = keychain_mask.clone();
	shared.locked.store(locked, Ordering::Relaxed);

	let config_path = Path::new(&wallet_config.data_file_dir)
		.join(WALLET_CONFIG_FILE_NAME)
		.to_string_lossy()
		.to_string();

	let ctx = WorkerCtx {
		wallet_inst: owner_api.wallet_inst.clone(),
		shared: shared.clone(),
		ui_tx: ui_tx.clone(),
		status_tx: status_tx.clone(),
		wallet_config: wallet_config.clone(),
		tor_config: tor_config.clone(),
		tls_conf: global_args.tls_conf.clone(),
		api_secret: global_args.api_secret.clone(),
		test_mode,
		config_path: config_file_path,
	};

	let (refresh_tx, refresh_rx) = mpsc::channel::<RefreshCtrl>();
	worker::spawn_refresher(ctx.clone(), refresh_rx);
	let _ = refresh_tx.send(RefreshCtrl::Now);

	install_panic_hook();
	enable_raw_mode().expect("Failed to enable raw terminal mode");
	let mut stdout = io::stdout();
	execute!(
		stdout,
		EnterAlternateScreen,
		EnableMouseCapture,
		EnableBracketedPaste
	)
	.expect("Failed to enter alternate screen");
	let terminal =
		Terminal::new(CrosstermBackend::new(stdout)).expect("Failed to initialize terminal");

	let mut controller = Controller {
		terminal,
		app: App::new(global_args.account.clone(), locked),
		owner_api,
		keychain_mask,
		wallet_config: wallet_config.clone(),
		tor_config: tor_config.clone(),
		global_wallet_args: global_args,
		shared,
		ctx,
		config_path,
		logs_rx,
		status_rx,
		ui_rx,
		refresh_tx,
		needs_redraw: true,
		last_draw: Instant::now(),
	};

	while controller.step() {}
	controller.teardown();

	Ok(())
}
