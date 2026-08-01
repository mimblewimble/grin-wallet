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

//! Editable wallet settings. Press Enter on a row to edit; persisted
//! settings go through the global config instance (#769) so multi-wallet
//! caches stay coherent and config listeners (e.g. foreign listener Tor
//! restart) are notified. Session-only settings apply immediately.

use crate::tui::app::SharedState;
use grin_wallet_config::config::{get_global_config, update_global_config};
use grin_wallet_config::{TorConfig, WalletConfig};
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, ListState, Row, Table, TableState};
use ratatui::Frame;
use std::path::Path;
use std::sync::atomic::Ordering;

#[derive(Copy, Clone, PartialEq)]
pub enum SettingKind {
	NodeAddr,
	ForeignPort,
	OwnerPort,
	IncludeForeign,
	TorListener,
	SocksAddr,
	SkipTorSend,
	MinConf,
}

pub struct SettingSpec {
	pub label: &'static str,
	pub kind: SettingKind,
	pub hint: &'static str,
	/// Whether a change only takes effect after restarting running
	/// listeners / the wallet
	pub restart: bool,
	/// Persisted to grin-wallet.toml (vs. session-only)
	pub persisted: bool,
}

pub static SETTINGS: &[SettingSpec] = &[
	SettingSpec {
		label: "Node API address",
		kind: SettingKind::NodeAddr,
		hint: "e.g. http://127.0.0.1:3413",
		restart: true,
		persisted: true,
	},
	SettingSpec {
		label: "Foreign API listen port",
		kind: SettingKind::ForeignPort,
		hint: "port number, e.g. 3415",
		restart: true,
		persisted: true,
	},
	SettingSpec {
		label: "Owner API listen port",
		kind: SettingKind::OwnerPort,
		hint: "port number, e.g. 3420",
		restart: true,
		persisted: true,
	},
	SettingSpec {
		label: "Owner API includes foreign",
		kind: SettingKind::IncludeForeign,
		hint: "true or false",
		restart: true,
		persisted: true,
	},
	SettingSpec {
		label: "Start Tor listener",
		kind: SettingKind::TorListener,
		hint: "true or false",
		restart: true,
		persisted: true,
	},
	SettingSpec {
		label: "Tor socks proxy address",
		kind: SettingKind::SocksAddr,
		hint: "e.g. 127.0.0.1:59050",
		restart: true,
		persisted: true,
	},
	SettingSpec {
		label: "Skip Tor send attempt",
		kind: SettingKind::SkipTorSend,
		hint: "true or false",
		restart: false,
		persisted: true,
	},
	SettingSpec {
		label: "Balance min confirmations",
		kind: SettingKind::MinConf,
		hint: "whole number (session only, not saved)",
		restart: false,
		persisted: false,
	},
];

/// Prefer the global config instance when available so Settings reflects
/// Owner-API / multi-wallet updates, not only the TUI's local snapshot.
pub fn effective_configs(
	config_path: &Path,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
) -> (WalletConfig, TorConfig) {
	match get_global_config(config_path) {
		Ok(global) => (global.members.wallet.clone(), global.tor_config()),
		Err(_) => (wallet_config.clone(), tor_config.clone()),
	}
}

/// The value currently in effect for a setting
pub fn current_value(
	kind: SettingKind,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	shared: &SharedState,
) -> String {
	match kind {
		SettingKind::NodeAddr => wallet_config.check_node_api_http_addr.clone(),
		SettingKind::ForeignPort => wallet_config.api_listen_port.to_string(),
		SettingKind::OwnerPort => wallet_config
			.owner_api_listen_port
			.map(|p| p.to_string())
			.unwrap_or_default(),
		SettingKind::IncludeForeign => wallet_config
			.owner_api_include_foreign
			.unwrap_or(false)
			.to_string(),
		SettingKind::TorListener => tor_config.use_tor_listener.to_string(),
		SettingKind::SocksAddr => tor_config.socks_proxy_addr.clone(),
		SettingKind::SkipTorSend => tor_config.skip_send_attempt.unwrap_or(false).to_string(),
		SettingKind::MinConf => shared.min_conf.load(Ordering::Relaxed).to_string(),
	}
}

fn parse_bool(v: &str) -> Result<bool, String> {
	match v.trim().to_lowercase().as_str() {
		"true" | "yes" | "1" => Ok(true),
		"false" | "no" | "0" => Ok(false),
		_ => Err("enter true or false".to_string()),
	}
}

fn parse_port(v: &str) -> Result<u16, String> {
	v.trim()
		.parse::<u16>()
		.map_err(|_| "enter a valid port number".to_string())
}

/// Validate and apply a new value via `update_global_config` (atomic save +
/// multi-wallet cache + listener notify from #769). Local TUI snapshots are
/// only updated after that succeeds.
pub fn apply(
	setting: &SettingSpec,
	value: &str,
	config_path: &str,
	wallet_config: &mut WalletConfig,
	tor_config: &mut TorConfig,
	shared: &SharedState,
) -> Result<String, String> {
	let value = value.trim();

	// Session-only settings short-circuit
	if let SettingKind::MinConf = setting.kind {
		let v = value
			.parse::<u64>()
			.map_err(|_| "enter a whole number".to_string())?;
		shared.min_conf.store(v, Ordering::Relaxed);
		return Ok(format!(
			"Balance minimum confirmations set to {} for this session.",
			v
		));
	}

	// Validate before touching the global config / disk.
	let parsed = match setting.kind {
		SettingKind::NodeAddr => {
			if value.is_empty() {
				return Err("address cannot be empty".to_string());
			}
			ParsedSetting::NodeAddr(value.to_string())
		}
		SettingKind::ForeignPort => ParsedSetting::ForeignPort(parse_port(value)?),
		SettingKind::OwnerPort => ParsedSetting::OwnerPort(parse_port(value)?),
		SettingKind::IncludeForeign => ParsedSetting::IncludeForeign(parse_bool(value)?),
		SettingKind::TorListener => ParsedSetting::TorListener(parse_bool(value)?),
		SettingKind::SocksAddr => {
			if value.is_empty() {
				return Err("address cannot be empty".to_string());
			}
			ParsedSetting::SocksAddr(value.to_string())
		}
		SettingKind::SkipTorSend => ParsedSetting::SkipTorSend(parse_bool(value)?),
		SettingKind::MinConf => unreachable!(),
	};

	let path = Path::new(config_path);
	update_global_config(path, |config| {
		match &parsed {
			ParsedSetting::NodeAddr(v) => {
				config.members.wallet.check_node_api_http_addr = v.clone();
			}
			ParsedSetting::ForeignPort(p) => {
				config.members.wallet.api_listen_port = *p;
			}
			ParsedSetting::OwnerPort(p) => {
				config.members.wallet.owner_api_listen_port = Some(*p);
			}
			ParsedSetting::IncludeForeign(b) => {
				config.members.wallet.owner_api_include_foreign = Some(*b);
			}
			ParsedSetting::TorListener(b) => {
				let fallback = config.tor_config();
				config.members.tor.get_or_insert(fallback).use_tor_listener = *b;
			}
			ParsedSetting::SocksAddr(v) => {
				let fallback = config.tor_config();
				config.members.tor.get_or_insert(fallback).socks_proxy_addr = v.clone();
			}
			ParsedSetting::SkipTorSend(b) => {
				let fallback = config.tor_config();
				config.members.tor.get_or_insert(fallback).skip_send_attempt = Some(*b);
			}
		}
		Ok(())
	})
	.map_err(|e| format!("unable to update {}: {}", config_path, e))?;

	// Refresh local snapshots from the global instance (source of truth).
	let global = get_global_config(path)
		.map_err(|e| format!("unable to read updated config {}: {}", config_path, e))?;
	*wallet_config = global.members.wallet.clone();
	*tor_config = global.tor_config();

	let mut notice = format!("Saved '{}' to {}.", setting.label, config_path);
	if setting.restart {
		notice.push_str(" Takes effect after restart.");
	}
	Ok(notice)
}

enum ParsedSetting {
	NodeAddr(String),
	ForeignPort(u16),
	OwnerPort(u16),
	IncludeForeign(bool),
	TorListener(bool),
	SocksAddr(String),
	SkipTorSend(bool),
}

pub fn draw(
	f: &mut Frame,
	area: Rect,
	list_state: &ListState,
	config_path: &str,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	shared: &SharedState,
) {
	let (eff_wallet, eff_tor) =
		effective_configs(Path::new(config_path), wallet_config, tor_config);

	let rows: Vec<Row> = SETTINGS
		.iter()
		.map(|s| {
			let mut label = s.label.to_string();
			if !s.persisted {
				label.push_str(" (session)");
			}
			Row::new(vec![
				Cell::from(label),
				Cell::from(current_value(s.kind, &eff_wallet, &eff_tor, shared)),
			])
		})
		.collect();

	let widths = [Constraint::Percentage(40), Constraint::Percentage(60)];
	let table = Table::new(rows, widths)
		.header(Row::new(vec!["Setting", "Value"]))
		.block(
			Block::default()
				.borders(Borders::ALL)
				.title("Settings - Enter to edit, saved via global config"),
		)
		.row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

	let mut table_state = TableState::default();
	table_state.select(list_state.selected());
	f.render_stateful_widget(table, area, &mut table_state);
}
