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
//! settings are written back to `grin-wallet.toml` (comments preserved by
//! the config crate's writer), session settings apply immediately.

use crate::tui::app::SharedState;
use grin_wallet_config::{GlobalWalletConfig, TorConfig, WalletConfig};
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, ListState, Row, Table, TableState};
use ratatui::Frame;
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

/// Validate and apply a new value: update the in-memory configs, persist
/// to grin-wallet.toml when applicable, and return the notice to show.
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

	// Validate & apply to the in-memory copies first
	match setting.kind {
		SettingKind::NodeAddr => {
			if value.is_empty() {
				return Err("address cannot be empty".to_string());
			}
			wallet_config.check_node_api_http_addr = value.to_string();
		}
		SettingKind::ForeignPort => wallet_config.api_listen_port = parse_port(value)?,
		SettingKind::OwnerPort => wallet_config.owner_api_listen_port = Some(parse_port(value)?),
		SettingKind::IncludeForeign => {
			wallet_config.owner_api_include_foreign = Some(parse_bool(value)?)
		}
		SettingKind::TorListener => tor_config.use_tor_listener = parse_bool(value)?,
		SettingKind::SocksAddr => {
			if value.is_empty() {
				return Err("address cannot be empty".to_string());
			}
			tor_config.socks_proxy_addr = value.to_string();
		}
		SettingKind::SkipTorSend => tor_config.skip_send_attempt = Some(parse_bool(value)?),
		SettingKind::MinConf => unreachable!(),
	}

	// Persist: reload the on-disk config so we only change this one key,
	// then write it back through the comment-preserving writer.
	let mut global_config = GlobalWalletConfig::new(config_path)
		.map_err(|e| format!("unable to load {}: {}", config_path, e))?;
	{
		let members = global_config
			.members
			.as_mut()
			.ok_or_else(|| "config file has no members".to_string())?;
		match setting.kind {
			SettingKind::NodeAddr => {
				members.wallet.check_node_api_http_addr = value.to_string();
			}
			SettingKind::ForeignPort => {
				members.wallet.api_listen_port = wallet_config.api_listen_port;
			}
			SettingKind::OwnerPort => {
				members.wallet.owner_api_listen_port = wallet_config.owner_api_listen_port;
			}
			SettingKind::IncludeForeign => {
				members.wallet.owner_api_include_foreign =
					wallet_config.owner_api_include_foreign;
			}
			SettingKind::TorListener | SettingKind::SocksAddr | SettingKind::SkipTorSend => {
				let tor = members.tor.get_or_insert_with(|| tor_config.clone());
				tor.use_tor_listener = tor_config.use_tor_listener;
				tor.socks_proxy_addr = tor_config.socks_proxy_addr.clone();
				tor.skip_send_attempt = tor_config.skip_send_attempt;
			}
			SettingKind::MinConf => unreachable!(),
		}
	}
	global_config
		.write_to_file(config_path, false, None, None)
		.map_err(|e| format!("unable to write {}: {}", config_path, e))?;

	let mut notice = format!("Saved '{}' to {}.", setting.label, config_path);
	if setting.restart {
		notice.push_str(" Takes effect after restart.");
	}
	Ok(notice)
}

/// Draw the settings view
pub fn draw(
	f: &mut Frame,
	area: Rect,
	list_state: &ListState,
	wallet_config: &WalletConfig,
	tor_config: &TorConfig,
	shared: &SharedState,
) {
	let rows: Vec<Row> = SETTINGS
		.iter()
		.map(|s| {
			let mut label = s.label.to_string();
			if !s.persisted {
				label.push_str(" (session)");
			}
			Row::new(vec![
				Cell::from(label),
				Cell::from(current_value(s.kind, wallet_config, tor_config, shared)),
			])
		})
		.collect();

	let widths = [Constraint::Percentage(40), Constraint::Percentage(60)];
	let table = Table::new(rows, widths)
		.header(Row::new(vec!["Setting", "Value"]))
		.block(
			Block::default()
				.borders(Borders::ALL)
				.title("Settings - Enter to edit, saved to grin-wallet.toml"),
		)
		.row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

	let mut table_state = TableState::default();
	table_state.select(list_state.selected());
	f.render_stateful_widget(table, area, &mut table_state);
}
