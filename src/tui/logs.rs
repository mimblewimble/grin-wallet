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

//! Log display: newest entries anchored to the bottom of the pane.
//! Uses ratatui's Unicode-aware wrap so wide characters reflow correctly.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::App;
use log::Level;

fn color(level: Level) -> Color {
	match level {
		Level::Info => Color::Green,
		Level::Warn => Color::Yellow,
		Level::Error => Color::Red,
		_ => Color::White,
	}
}

/// Draw the logs view. Newest entries are kept; Paragraph + Wrap handles
/// reflow using terminal column widths (not raw char counts).
pub fn draw(f: &mut Frame, area: Rect, app: &App) {
	// Cap to a few screens of source lines so wrap stays cheap; newest first
	// in the ring buffer, so reverse for chronological display.
	let max_source = (area.height as usize).saturating_mul(4).max(32);
	let lines: Vec<Line> = app
		.logs
		.iter()
		.take(max_source)
		.rev()
		.map(|entry| {
			Line::from(Span::styled(
				entry.log.trim_end_matches('\n').to_string(),
				Style::default().fg(color(entry.level)),
			))
		})
		.collect();

	// Approximate bottom-anchoring: if we have more source lines than the
	// pane height, scroll by the excess (wrap may add a few more rows).
	let scroll = lines.len().saturating_sub(area.height as usize) as u16;
	let paragraph = Paragraph::new(lines)
		.wrap(Wrap { trim: false })
		.scroll((scroll, 0));
	f.render_widget(paragraph, area);
}
