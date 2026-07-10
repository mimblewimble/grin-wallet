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

//! Read-only view of the wallet/tor configuration currently in effect.
//! Edit `grin-wallet.toml` and restart to change these (issue #751 asks for
//! "possible config change" - full in-place TOML editing is left as a
//! follow-up, but the values that matter day-to-day are all visible here).

use grin_wallet_config::{TorConfig, WalletConfig};
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

fn line(label: &str, value: impl Into<String>) -> Line<'static> {
	Line::from(format!("{:<34}{}", label, value.into()))
}

/// Draw the settings/config view
pub fn draw(f: &mut Frame, area: Rect, wallet_config: &WalletConfig, tor_config: &TorConfig) {
	let mut lines: Vec<Line> = Vec::new();

	lines.push(line("Data Directory:", wallet_config.data_file_dir.clone()));
	lines.push(line(
		"Node API Address:",
		wallet_config.check_node_api_http_addr.clone(),
	));
	lines.push(line(
		"Owner API Listen Port:",
		wallet_config
			.owner_api_listen_port
			.map(|p| p.to_string())
			.unwrap_or_else(|| "-".to_string()),
	));
	lines.push(line(
		"Foreign API Listen Port:",
		wallet_config.api_listen_port.to_string(),
	));
	lines.push(line(
		"Owner API Includes Foreign:",
		wallet_config
			.owner_api_include_foreign
			.unwrap_or(false)
			.to_string(),
	));
	lines.push(Line::from(
		"--------------------------------------------------------------------",
	));
	lines.push(line("Tor Listener Enabled:", tor_config.use_tor_listener.to_string()));
	lines.push(line(
		"Tor Skip Send Attempt:",
		tor_config.skip_send_attempt.unwrap_or(false).to_string(),
	));
	lines.push(line("Tor Socks Proxy Address:", tor_config.socks_proxy_addr.clone()));
	lines.push(line("Tor Send Config Directory:", tor_config.send_config_dir.clone()));
	lines.push(Line::from(""));
	lines.push(Line::from(
		"To change these, edit grin-wallet.toml in the data directory above and restart.",
	));

	let paragraph = Paragraph::new(lines);
	f.render_widget(paragraph, area);
}
