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

//! Outputs view

use crate::tui::app::App;
use grin_core::core::amount_to_hr_string;
use grin_util::ToHex;
use grin_wallet_libwallet::OutputCommitMapping;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

/// Format the reconstructed mapping commit (same source as the CLI display).
fn short_commit(o: &OutputCommitMapping) -> String {
	let c = o.commit.as_ref().to_hex();
	if c.len() > 16 {
		format!("{}...", &c[..16])
	} else {
		c
	}
}

fn output_row(o: &OutputCommitMapping) -> Row<'static> {
	Row::new(vec![
		Cell::from(short_commit(o)),
		Cell::from(amount_to_hr_string(o.output.value, false)),
		Cell::from(format!("{:?}", o.output.status)),
		Cell::from(o.output.height.to_string()),
		Cell::from(if o.output.is_coinbase { "yes" } else { "no" }),
	])
}

const HEADERS: [&str; 5] = ["Commitment", "Value", "Status", "Height", "Coinbase"];
const WIDTHS: [u16; 5] = [30, 18, 18, 14, 10];

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
	if app.locked {
		f.render_widget(Paragraph::new("Wallet is locked."), area);
		return;
	}

	let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(area);

	f.render_widget(
		Paragraph::new(Line::from(format!(
			"Total: {} ({} spent outputs, toggle with 's')",
			app.view.outputs.len(),
			if app.show_spent { "showing" } else { "hiding" }
		))),
		chunks[0],
	);

	let rows: Vec<Row> = app.view.outputs.iter().map(output_row).collect();
	let widths: Vec<Constraint> = WIDTHS.iter().map(|w| Constraint::Percentage(*w)).collect();
	let table = Table::new(rows, widths)
		.header(Row::new(HEADERS.to_vec()))
		.block(Block::default().borders(Borders::ALL).title("Outputs"))
		.row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

	f.render_stateful_widget(table, chunks[1], &mut app.outputs_table);
}
