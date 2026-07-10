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

//! Terminal driver for the wallet TUI: sets up the alternate screen,
//! refreshes dashboard data from the Owner API, and - when an Actions form
//! is submitted - suspends the alternate screen to run the exact same
//! `wallet_args::parse_and_execute` dispatch the plain CLI uses, so every
//! wallet subcommand (including its existing interactive prompts) works
//! unchanged.

use crate::cmd::wallet_args;
use crate::tui::accounts;
use crate::tui::actions::{self, Modal};
use crate::tui::app::{App, Dialog, Focus, Tab};
use crate::tui::logs as logs_view;
use crate::tui::menu;
use crate::tui::outputs;
use crate::tui::settings;
use crate::tui::status;
use crate::tui::txs;
use clap::App as ClapApp;
use crossterm::event::{
	self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton,
	MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
	disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use grin_keychain as keychain;
use grin_util::logger::LogEntry;
use grin_util::secp::key::SecretKey;
use grin_util::Mutex;
use grin_wallet_api::Owner;
use grin_wallet_config::{TorConfig, WalletConfig};
use grin_wallet_controller::command::GlobalArgs;
use grin_wallet_controller::Error;
use grin_wallet_impls::DefaultWalletImpl;
use grin_wallet_libwallet::{NodeClient, StatusMessage, WalletInst, WalletLCProvider};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{self, Stdout, Write};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Backend = CrosstermBackend<Stdout>;

/// How often the dashboard re-polls the Owner API. Cheap because
/// `start_updater` is running, which forces `refresh_from_node` to act as a
/// local read regardless of what's passed here.
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
/// Redraw at least this often even without input or new data.
const MAX_REDRAW_INTERVAL: Duration = Duration::from_millis(250);
/// How far PageUp/PageDown move a table selection
const TABLE_PAGE_SIZE: i64 = 10;
/// Default minimum-confirmations used for the live balance view
const DEFAULT_MIN_CONF: u64 = 10;

fn install_panic_hook() {
	let original_hook = std::panic::take_hook();
	std::panic::set_hook(Box::new(move |panic_info| {
		let _ = disable_raw_mode();
		let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
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

/// Parse `argv` as a `grin-wallet` command line and execute it. `open`/
/// `close` are intercepted directly (they only exist as special cases
/// inside the interactive CLI, see `src/cli/cli.rs`); every other
/// subcommand is handed to the exact same dispatch the plain CLI uses.
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
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
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
			let password = wallet_args::prompt_password(&global_wallet_args.password);
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
		("close", Some(_)) => {
			if let Err(e) = owner_api.close_wallet(None) {
				println!("Failed to close wallet: {}", e);
			} else {
				println!("Wallet locked.");
			}
			*keychain_mask = None;
			*locked = true;
			Ok(())
		}
		_ => wallet_args::parse_and_execute(
			owner_api,
			keychain_mask.clone(),
			wallet_config,
			tor_config,
			global_wallet_args,
			&matches,
			test_mode,
			true,
		),
	}
}

fn draw_dialog(f: &mut Frame, area: Rect, dialog: &Dialog) {
	let popup_area = centered_rect(60, 20, area);
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

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
	let vertical = Layout::vertical([
		Constraint::Percentage((100 - percent_y) / 2),
		Constraint::Percentage(percent_y),
		Constraint::Percentage((100 - percent_y) / 2),
	])
	.split(r);

	Layout::horizontal([
		Constraint::Percentage((100 - percent_x) / 2),
		Constraint::Percentage(percent_x),
		Constraint::Percentage((100 - percent_x) / 2),
	])
	.split(vertical[1])[1]
}

fn draw_frame(f: &mut Frame, app: &mut App, wallet_config: &WalletConfig, tor_config: &TorConfig) {
	let size = f.area();
	let outer = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(size);

	let title = format!(
		"Grin Wallet TUI - Account: {}{}",
		app.view.account,
		if app.locked { " (locked)" } else { "" }
	);
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
		Tab::Status => status::draw(f, content_area, app),
		Tab::Accounts => accounts::draw(f, content_area, app),
		Tab::Outputs => outputs::draw(f, content_area, app),
		Tab::Transactions => txs::draw(f, content_area, app),
		Tab::Actions => actions::draw(f, content_area, &mut app.actions_list),
		Tab::Settings => settings::draw(f, content_area, wallet_config, tor_config),
		Tab::Logs => logs_view::draw(f, content_area, app),
	}

	if let Some(Modal::Form(form)) = &app.modal {
		actions::draw_form(f, size, form);
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
	test_mode: bool,
	logs_rx: Option<mpsc::Receiver<LogEntry>>,
	status_rx: mpsc::Receiver<StatusMessage>,
	needs_redraw: bool,
	last_draw: Instant,
	last_refresh: Instant,
}

impl<L, C, K> Controller<L, C, K>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	fn refresh(&mut self) {
		if self.app.locked {
			return;
		}
		let m = self.keychain_mask.as_ref();

		match self
			.owner_api
			.retrieve_summary_info(m, true, DEFAULT_MIN_CONF)
		{
			Ok((validated, info)) => {
				self.app.view.info = Some(info);
				self.app.view.validated = validated;
				self.app.view.last_error = None;
			}
			Err(e) => self.app.view.last_error = Some(e.to_string()),
		}
		if let Ok(accounts) = self.owner_api.accounts(m) {
			self.app.view.accounts = accounts;
		}
		if let Ok((_, outputs)) =
			self.owner_api
				.retrieve_outputs(m, self.app.show_spent, true, None)
		{
			self.app.view.outputs = outputs;
		}
		if let Ok((_, txs)) = self.owner_api.retrieve_txs(m, true, None, None, None) {
			self.app.view.txs = txs;
		}
		if let Ok(height) = self.owner_api.node_height(m) {
			self.app.view.node_height = Some(height.height);
		}
		if self.app.view.address.is_none() {
			if let Ok(addr) = self.owner_api.get_slatepack_address(m, 0) {
				self.app.view.address = Some(format!("{}", addr));
			}
		}
		self.needs_redraw = true;
	}

	fn on_down(&mut self) {
		match self.app.focus {
			Focus::Menu => self.app.select_menu_next(),
			Focus::Content => match self.app.tab {
				Tab::Actions => self.move_actions_selection(1),
				_ => self.move_table_selection(1),
			},
		}
	}

	fn on_up(&mut self) {
		match self.app.focus {
			Focus::Menu => self.app.select_menu_prev(),
			Focus::Content => match self.app.tab {
				Tab::Actions => self.move_actions_selection(-1),
				_ => self.move_table_selection(-1),
			},
		}
	}

	fn move_actions_selection(&mut self, delta: i64) {
		let len = actions::ACTIONS.len() as i64;
		if len == 0 {
			return;
		}
		let current = self.app.actions_list.selected().unwrap_or(0) as i64;
		let next = (current + delta).rem_euclid(len);
		self.app.actions_list.select(Some(next as usize));
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

	fn handle_key(&mut self, code: KeyCode) {
		if self.app.dialog.is_some() {
			self.app.dialog = None;
			return;
		}

		if let Some(Modal::Form(form)) = &mut self.app.modal {
			let is_bool_focused = matches!(
				form.values.get(form.focus),
				Some(actions::FieldValue::Bool(_))
			);
			match code {
				KeyCode::Esc => self.app.modal = None,
				KeyCode::Tab | KeyCode::Down => form.next_field(),
				KeyCode::BackTab | KeyCode::Up => form.prev_field(),
				KeyCode::Left => form.left(),
				KeyCode::Right => form.right(),
				KeyCode::Home => form.home(),
				KeyCode::End => form.end(),
				KeyCode::Backspace => form.backspace(),
				KeyCode::Delete => form.delete(),
				KeyCode::Char(' ') if is_bool_focused => form.toggle_focused(),
				KeyCode::Enter => {
					if is_bool_focused {
						form.toggle_focused();
					} else if form.focus + 1 < form.field_count() {
						form.next_field();
					} else {
						let argv = form.build_argv();
						self.app.modal = None;
						self.app.pending_action = Some(argv);
					}
				}
				KeyCode::Char(c) => form.insert(c),
				_ => {}
			}
			return;
		}

		match code {
			KeyCode::Char('q') => self.app.should_quit = true,
			KeyCode::Char('j') | KeyCode::Down => self.on_down(),
			KeyCode::Char('k') | KeyCode::Up => self.on_up(),
			KeyCode::PageDown => self.move_table_selection(TABLE_PAGE_SIZE),
			KeyCode::PageUp => self.move_table_selection(-TABLE_PAGE_SIZE),
			KeyCode::Home => self.move_table_selection(i64::MIN),
			KeyCode::End => self.move_table_selection(i64::MAX),
			KeyCode::Tab => self.app.select_menu_next(),
			KeyCode::Char('s') => self.app.show_spent = !self.app.show_spent,
			KeyCode::Enter => {
				if self.app.focus == Focus::Menu {
					self.app.focus = Focus::Content;
				} else if self.app.tab == Tab::Actions {
					if let Some(idx) = self.app.actions_list.selected() {
						self.app.modal = Some(Modal::Form(actions::FormState::new(idx)));
					}
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

	/// Leave the alternate screen, run `argv` through the exact same
	/// dispatch the plain CLI uses (with all its existing interactive
	/// prompts, network calls and stdout output happening normally), then
	/// wait for the user and resume.
	fn run_action(&mut self, argv: Vec<String>) {
		let _ = disable_raw_mode();
		let _ = execute!(
			self.terminal.backend_mut(),
			LeaveAlternateScreen,
			DisableMouseCapture
		);

		println!("\n=== Running: {} ===\n", argv[1..].join(" "));
		let result = run_subcommand(
			argv,
			&mut self.owner_api,
			&mut self.keychain_mask,
			&mut self.app.locked,
			&self.wallet_config,
			&self.tor_config,
			&self.global_wallet_args,
			self.test_mode,
		);

		match &result {
			Ok(()) => println!("\nCommand completed."),
			Err(e) => println!("\nCommand failed: {}", e),
		}
		println!("\nPress Enter to return to the dashboard...");
		let mut discard = String::new();
		let _ = io::stdin().read_line(&mut discard);

		let _ = enable_raw_mode();
		let _ = execute!(
			self.terminal.backend_mut(),
			EnterAlternateScreen,
			EnableMouseCapture
		);
		let _ = self.terminal.clear();
	}

	fn draw(&mut self) {
		let app = &mut self.app;
		let wallet_config = &self.wallet_config;
		let tor_config = &self.tor_config;
		let _ = self
			.terminal
			.draw(|f| draw_frame(f, app, wallet_config, tor_config));
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

		if self.last_refresh.elapsed() >= REFRESH_INTERVAL {
			self.refresh();
			self.last_refresh = Instant::now();
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
				Ok(Event::Resize(_, _)) => self.needs_redraw = true,
				_ => {}
			}
		}

		if let Some(argv) = self.app.pending_action.take() {
			self.run_action(argv);
			self.refresh();
			self.needs_redraw = true;
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
			DisableMouseCapture
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
			DisableMouseCapture
		);
	}
}

/// Run the interactive wallet TUI. Mirrors `cli::command_loop`'s role: a
/// long-lived process holding an open wallet + keychain mask across many
/// commands, but presented as a full-screen dashboard instead of a REPL.
pub fn run<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	global_wallet_args: &GlobalArgs,
	test_mode: bool,
	logs_rx: Option<mpsc::Receiver<LogEntry>>,
) -> Result<(), Error>
where
	DefaultWalletImpl<'static, C>: WalletInst<'static, L, C, K>,
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (status_tx, status_rx) = mpsc::channel::<StatusMessage>();
	let mut owner_api = Owner::new(wallet_inst, Some(status_tx));
	let mut keychain_mask: Option<SecretKey> = None;
	let mut locked = true;

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
				global_wallet_args,
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
		global_wallet_args,
		test_mode,
	) {
		println!("Failed to open wallet: {}", e);
		return Ok(());
	}
	if locked {
		println!("Could not open wallet, exiting.");
		return Ok(());
	}

	let _ = owner_api.start_updater(keychain_mask.as_ref(), Duration::from_secs(30));

	install_panic_hook();
	enable_raw_mode().expect("Failed to enable raw terminal mode");
	let mut stdout = io::stdout();
	execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
		.expect("Failed to enter alternate screen");
	let terminal =
		Terminal::new(CrosstermBackend::new(stdout)).expect("Failed to initialize terminal");

	let mut controller = Controller {
		terminal,
		app: App::new(global_wallet_args.account.clone(), locked),
		owner_api,
		keychain_mask,
		wallet_config: wallet_config.clone(),
		tor_config: tor_config.clone(),
		global_wallet_args: global_wallet_args.clone(),
		test_mode,
		logs_rx,
		status_rx,
		needs_redraw: true,
		last_draw: Instant::now(),
		last_refresh: Instant::now() - REFRESH_INTERVAL,
	};

	while controller.step() {}
	controller.teardown();

	Ok(())
}
