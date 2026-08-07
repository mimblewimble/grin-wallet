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

//! Transactions view

use crate::tui::app::App;
use grin_core::core::amount_to_hr_string;
use grin_wallet_libwallet::TxLogEntry;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

fn tx_row(t: &TxLogEntry) -> Row<'static> {
	let slate_id = t
		.tx_slate_id
		.map(|u| u.to_string())
		.unwrap_or_else(|| "-".to_string());
	Row::new(vec![
		Cell::from(t.id.to_string()),
		Cell::from(format!("{:?}", t.tx_type)),
		Cell::from(slate_id),
		Cell::from(amount_to_hr_string(t.amount_credited, false)),
		Cell::from(amount_to_hr_string(t.amount_debited, false)),
		Cell::from(if t.confirmed { "yes" } else { "no" }),
		Cell::from(t.creation_ts.format("%Y-%m-%d %H:%M:%S").to_string()),
	])
}

const HEADERS: [&str; 7] = [
	"Id",
	"Type",
	"Slate Id",
	"Credited",
	"Debited",
	"Confirmed",
	"Created",
];
const WIDTHS: [u16; 7] = [5, 16, 20, 14, 14, 10, 21];

/// Draw the transactions view
pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
	if app.locked {
		f.render_widget(Paragraph::new("Wallet is locked."), area);
		return;
	}

	let rows: Vec<Row> = app.view.txs.iter().map(tx_row).collect();
	let widths: Vec<Constraint> = WIDTHS.iter().map(|w| Constraint::Length(*w)).collect();
	let table = Table::new(rows, widths)
		.header(Row::new(HEADERS.to_vec()))
		.block(
			Block::default()
				.borders(Borders::ALL)
				.title("Transactions - use Actions to cancel/repost/export a proof"),
		)
		.row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

	f.render_stateful_widget(table, area, &mut app.txs_table);
}
