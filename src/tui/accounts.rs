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

//! Accounts view

use crate::tui::app::App;
use grin_wallet_libwallet::AcctPathMapping;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

fn account_row(a: &AcctPathMapping) -> Row<'static> {
	Row::new(vec![
		Cell::from(a.label.clone()),
		Cell::from(format!("{}", a.path)),
	])
}

const HEADERS: [&str; 2] = ["Account Name", "Parent BIP-32 Derivation Path"];
const WIDTHS: [u16; 2] = [30, 70];

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
	if app.locked {
		f.render_widget(Paragraph::new("Wallet is locked."), area);
		return;
	}

	let rows: Vec<Row> = app.view.accounts.iter().map(account_row).collect();
	let widths: Vec<Constraint> = WIDTHS.iter().map(|w| Constraint::Percentage(*w)).collect();
	let table = Table::new(rows, widths)
		.header(Row::new(HEADERS.to_vec()))
		.block(
			Block::default()
				.borders(Borders::ALL)
				.title("Accounts - use Actions > Create Account to add one"),
		)
		.row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

	f.render_stateful_widget(table, area, &mut app.accounts_table);
}
