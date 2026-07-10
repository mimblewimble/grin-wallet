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

//! Central application state for the wallet TUI

use crate::tui::modals::Modal;
use grin_util::logger::LogEntry;
use grin_util::secp::key::SecretKey;
use grin_util::Mutex;
use grin_wallet_libwallet::{AcctPathMapping, OutputCommitMapping, TxLogEntry, WalletInfo};
use ratatui::layout::Rect;
use ratatui::widgets::{ListState, TableState};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Number of log lines retained in the ring buffer
pub const LOG_BUFFER_SIZE: usize = 300;

/// Default minimum-confirmations used for the live balance view
pub const DEFAULT_MIN_CONF: u64 = 10;

/// Top level tabs, in the order they appear in the side menu
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Tab {
	Status,
	Accounts,
	Outputs,
	Transactions,
	Actions,
	Settings,
	Logs,
}

impl Tab {
	pub const ALL: [Tab; 7] = [
		Tab::Status,
		Tab::Accounts,
		Tab::Outputs,
		Tab::Transactions,
		Tab::Actions,
		Tab::Settings,
		Tab::Logs,
	];

	pub fn title(&self) -> &'static str {
		match self {
			Tab::Status => "Account Status",
			Tab::Accounts => "Accounts",
			Tab::Outputs => "Outputs",
			Tab::Transactions => "Transactions",
			Tab::Actions => "Actions",
			Tab::Settings => "Settings",
			Tab::Logs => "Logs",
		}
	}

	pub fn index(&self) -> usize {
		Tab::ALL.iter().position(|t| t == self).unwrap_or(0)
	}
}

/// Which pane currently receives key input
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Focus {
	Menu,
	Content,
}

/// State shared between the UI thread and background worker threads
pub struct SharedState {
	/// Current keychain mask, updated on open/close
	pub mask: Mutex<Option<SecretKey>>,
	/// Whether the wallet is currently locked
	pub locked: AtomicBool,
	/// Name of the operation currently running on a worker thread, if any
	pub busy: Mutex<Option<String>>,
	/// Active account name
	pub account: Mutex<String>,
	/// Minimum confirmations used by the balance refresher
	pub min_conf: AtomicU64,
	/// Whether spent outputs are included in the outputs view
	pub show_spent: AtomicBool,
	/// Whether the foreign (receive) listener is running
	pub listener_running: AtomicBool,
	/// Whether the owner API listener is running
	pub owner_api_running: AtomicBool,
}

impl SharedState {
	pub fn new(account: String) -> SharedState {
		SharedState {
			mask: Mutex::new(None),
			locked: AtomicBool::new(true),
			busy: Mutex::new(None),
			account: Mutex::new(account),
			min_conf: AtomicU64::new(DEFAULT_MIN_CONF),
			show_spent: AtomicBool::new(false),
			listener_running: AtomicBool::new(false),
			owner_api_running: AtomicBool::new(false),
		}
	}

	pub fn busy_with(&self) -> Option<String> {
		self.busy.lock().clone()
	}

	pub fn is_locked(&self) -> bool {
		self.locked.load(Ordering::Relaxed)
	}
}

/// A snapshot of wallet data, built by the background refresher thread and
/// replaced wholesale on each refresh tick.
#[derive(Default)]
pub struct WalletView {
	pub account: String,
	pub info: Option<WalletInfo>,
	pub validated: bool,
	pub node_height: Option<u64>,
	pub accounts: Vec<AcctPathMapping>,
	pub outputs: Vec<OutputCommitMapping>,
	pub txs: Vec<TxLogEntry>,
	pub address: Option<String>,
	pub last_error: Option<String>,
}

/// A simple acknowledgement dialog
pub struct Dialog {
	pub text: String,
}

/// All mutable state the UI renders from.
pub struct App {
	pub tab: Tab,
	pub focus: Focus,
	pub locked: bool,
	pub view: WalletView,
	pub show_spent: bool,
	pub logs: VecDeque<LogEntry>,
	pub accounts_table: TableState,
	pub outputs_table: TableState,
	pub txs_table: TableState,
	pub actions_list: ListState,
	pub settings_list: ListState,
	pub modal: Option<Modal>,
	pub dialog: Option<Dialog>,
	pub should_quit: bool,
	/// Screen area of the menu list, stored at draw time for mouse hit-testing
	pub menu_area: Rect,
}

impl App {
	pub fn new(account: String, locked: bool) -> App {
		let mut actions_list = ListState::default();
		actions_list.select(Some(0));
		let mut settings_list = ListState::default();
		settings_list.select(Some(0));
		App {
			tab: Tab::Status,
			focus: Focus::Menu,
			locked,
			view: WalletView {
				account,
				..Default::default()
			},
			show_spent: false,
			logs: VecDeque::with_capacity(LOG_BUFFER_SIZE),
			accounts_table: TableState::default(),
			outputs_table: TableState::default(),
			txs_table: TableState::default(),
			actions_list,
			settings_list,
			modal: None,
			dialog: None,
			should_quit: false,
			menu_area: Rect::default(),
		}
	}

	/// Number of rows in the table currently on screen, if any
	pub fn current_table_len(&self) -> usize {
		match self.tab {
			Tab::Accounts => self.view.accounts.len(),
			Tab::Outputs => self.view.outputs.len(),
			Tab::Transactions => self.view.txs.len(),
			_ => 0,
		}
	}

	pub fn push_log(&mut self, entry: LogEntry) {
		self.logs.push_front(entry);
		if self.logs.len() > LOG_BUFFER_SIZE {
			self.logs.pop_back();
		}
	}

	pub fn select_menu_next(&mut self) {
		let next = (self.tab.index() + 1) % Tab::ALL.len();
		self.tab = Tab::ALL[next];
	}

	pub fn select_menu_prev(&mut self) {
		let len = Tab::ALL.len();
		let prev = (self.tab.index() + len - 1) % len;
		self.tab = Tab::ALL[prev];
	}
}
