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

//! Account status / balance view

use crate::tui::app::App;
use grin_core::core::amount_to_hr_string;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

fn line(label: &str, value: impl Into<String>) -> Line<'static> {
	Line::from(format!("{:<32}{}", label, value.into()))
}

const SEPARATOR: &str = "--------------------------------------------------------------------";

fn grin(amount: u64) -> String {
	amount_to_hr_string(amount, false)
}

/// Draw the account status/balance view
pub fn draw(f: &mut Frame, area: Rect, app: &App) {
	let mut lines: Vec<Line> = Vec::new();

	lines.push(line("Account:", app.view.account.clone()));
	if app.locked {
		lines.push(line("Wallet Status:", "Locked (use Actions > Open)"));
		let paragraph = Paragraph::new(lines);
		f.render_widget(paragraph, area);
		return;
	}
	lines.push(line("Wallet Status:", "Unlocked"));

	if let Some(err) = &app.view.last_error {
		lines.push(line("Last Error:", err.clone()));
	}
	if let Some(addr) = &app.view.address {
		lines.push(line("Slatepack Address:", addr.clone()));
	}
	if let Some(height) = app.view.node_height {
		lines.push(line("Node Height:", height.to_string()));
	}
	lines.push(line(
		"Data Refreshed:",
		if app.view.validated { "Yes" } else { "Pending" },
	));
	lines.push(Line::from(SEPARATOR));

	match &app.view.info {
		None => {
			lines.push(line("Balance:", "Loading..."));
		}
		Some(info) => {
			lines.push(line("Total:", grin(info.total)));
			lines.push(line("Currently Spendable:", grin(info.amount_currently_spendable)));
			lines.push(line("Awaiting Confirmation:", grin(info.amount_awaiting_confirmation)));
			lines.push(line("Awaiting Finalization:", grin(info.amount_awaiting_finalization)));
			lines.push(line("Locked by Unfinished Tx:", grin(info.amount_locked)));
			lines.push(line("Immature Coinbase:", grin(info.amount_immature)));
			lines.push(line("Reverted:", grin(info.amount_reverted)));
			lines.push(Line::from(SEPARATOR));
			lines.push(line(
				"Minimum Confirmations:",
				info.minimum_confirmations.to_string(),
			));
			lines.push(line(
				"Last Confirmed Height:",
				info.last_confirmed_height.to_string(),
			));
		}
	}

	let paragraph = Paragraph::new(lines);
	f.render_widget(paragraph, area);
}
