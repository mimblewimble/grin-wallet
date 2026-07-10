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

//! Modal dialogs layered over the dashboard: action forms, slatepack
//! paste input, scrollable output (with optional QR view), the pay
//! confirmation gate, row context menus, setting editors and the help
//! overlay.

use crate::tui::actions::FormState;
use crate::tui::form::TextField;
use crate::tui::worker::{PayParams, SlateOpParams};
use grin_wallet_libwallet::Slate;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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

/// A slatepack is being pasted for the given pending operation
pub struct SlatepackInputState {
	pub title: String,
	pub buffer: String,
	pub error: Option<String>,
	pub op: SlateOpParams,
}

/// Scrollable text/slatepack output, optionally with a QR view
pub struct OutputState {
	pub title: String,
	pub lines: Vec<String>,
	/// Text placed on the clipboard when the user presses 'c'
	pub copy: Option<String>,
	pub qr: Option<String>,
	pub show_qr: bool,
	pub scroll: u16,
}

impl OutputState {
	pub fn from_text(title: String, body: String, copy: Option<String>) -> OutputState {
		OutputState {
			title,
			lines: body.lines().map(|l| l.to_string()).collect(),
			copy,
			qr: None,
			show_qr: false,
			scroll: 0,
		}
	}
}

/// Confirmation gate before paying a parsed invoice
pub struct ConfirmPayState {
	pub amount: String,
	pub dest: String,
	pub params: PayParams,
	pub slate: Box<Slate>,
}

/// What a context-menu entry does when selected
pub enum ContextAction {
	/// Open the form for `ACTIONS[spec_idx]` with fields pre-filled
	OpenForm {
		spec_idx: usize,
		prefill: Vec<(&'static str, String)>,
	},
	/// Switch the active account
	SwitchAccount(String),
	/// Copy the given text to the terminal clipboard (OSC 52)
	Copy(String),
}

pub struct ContextMenuState {
	pub title: String,
	pub items: Vec<(String, ContextAction)>,
	pub selected: usize,
}

impl ContextMenuState {
	pub fn next(&mut self) {
		if !self.items.is_empty() {
			self.selected = (self.selected + 1) % self.items.len();
		}
	}
	pub fn prev(&mut self) {
		if !self.items.is_empty() {
			self.selected = (self.selected + self.items.len() - 1) % self.items.len();
		}
	}
}

/// A single setting being edited
pub struct EditSettingState {
	pub setting_idx: usize,
	pub field: TextField,
	pub error: Option<String>,
}

/// Why a password is being requested
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum PasswordPurpose {
	/// Unlock the wallet (`open`)
	Open,
	/// Decrypt and display the BIP39 recovery phrase (`recover`)
	Recover,
}

/// Masked password entry modal (never leaves the alternate screen)
pub struct PasswordState {
	pub purpose: PasswordPurpose,
	pub field: TextField,
	pub error: Option<String>,
}

impl PasswordState {
	pub fn new(purpose: PasswordPurpose) -> PasswordState {
		PasswordState {
			purpose,
			field: TextField::new(""),
			error: None,
		}
	}

	pub fn title(&self) -> &'static str {
		match self.purpose {
			PasswordPurpose::Open => "Open / Unlock Wallet",
			PasswordPurpose::Recover => "Show Recovery Phrase",
		}
	}
}

pub enum Modal {
	Form(FormState),
	SlatepackInput(SlatepackInputState),
	Output(OutputState),
	ConfirmPay(ConfirmPayState),
	Context(ContextMenuState),
	EditSetting(EditSettingState),
	Password(PasswordState),
	Help,
}

pub fn draw(f: &mut Frame, area: Rect, modal: &mut Modal) {
	match modal {
		Modal::Form(form) => crate::tui::actions::draw_form(f, area, form),
		Modal::SlatepackInput(state) => draw_slatepack_input(f, area, state),
		Modal::Output(state) => draw_output(f, area, state),
		Modal::ConfirmPay(state) => draw_confirm_pay(f, area, state),
		Modal::Context(state) => draw_context(f, area, state),
		Modal::EditSetting(state) => draw_edit_setting(f, area, state),
		Modal::Password(state) => draw_password(f, area, state),
		Modal::Help => draw_help(f, area),
	}
}

fn draw_password(f: &mut Frame, area: Rect, state: &PasswordState) {
	let popup = centered_rect(55, 30, area);
	f.render_widget(Clear, popup);
	let block = Block::default().borders(Borders::ALL).title(format!(
		"{} (Enter: submit, Esc: cancel)",
		state.title()
	));
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	let rows = Layout::vertical([
		Constraint::Length(1),
		Constraint::Length(1),
		Constraint::Length(1),
		Constraint::Length(1),
	])
	.split(inner);

	f.render_widget(
		Paragraph::new("Enter wallet password:"),
		rows[0],
	);
	// Mask the value so a shoulder-surfer can't read it off the screen
	let masked: String = "*".repeat(state.field.value.chars().count());
	f.render_widget(
		Paragraph::new(Line::from(vec![
			Span::raw("> "),
			Span::styled(masked, Style::default().add_modifier(Modifier::BOLD)),
		])),
		rows[1],
	);
	if let Some(err) = &state.error {
		f.render_widget(
			Paragraph::new(Line::from(Span::styled(
				err.clone(),
				Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
			))),
			rows[3],
		);
	}
}

fn draw_slatepack_input(f: &mut Frame, area: Rect, state: &SlatepackInputState) {
	let popup = centered_rect(80, 70, area);
	f.render_widget(Clear, popup);
	let block = Block::default().borders(Borders::ALL).title(format!(
		"{} - paste the slatepack, Enter: submit, Esc: cancel",
		state.title
	));
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	let rows = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);

	let text = if state.buffer.is_empty() {
		Paragraph::new("(paste an armored slatepack message here)")
			.style(Style::default().fg(Color::DarkGray))
			.wrap(Wrap { trim: false })
	} else {
		Paragraph::new(state.buffer.clone()).wrap(Wrap { trim: false })
	};
	f.render_widget(text, rows[0]);

	if let Some(err) = &state.error {
		let line = Line::from(Span::styled(
			err.clone(),
			Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
		));
		f.render_widget(Paragraph::new(line), rows[1]);
	}
}

fn draw_output(f: &mut Frame, area: Rect, state: &OutputState) {
	let popup = centered_rect(90, 90, area);
	f.render_widget(Clear, popup);
	let mut hints = vec!["Up/Down: scroll"];
	if state.copy.is_some() {
		hints.push("c: copy");
	}
	if state.qr.is_some() {
		hints.push("q: QR");
	}
	hints.push("Esc: close");
	let block = Block::default()
		.borders(Borders::ALL)
		.title(format!("{} ({})", state.title, hints.join(", ")));
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	if state.show_qr {
		if let Some(qr) = &state.qr {
			let lines: Vec<Line> = qr.lines().map(|l| Line::from(l.to_string())).collect();
			let paragraph = Paragraph::new(lines).scroll((state.scroll, 0));
			f.render_widget(paragraph, inner);
			return;
		}
	}

	let lines: Vec<Line> = state
		.lines
		.iter()
		.map(|l| Line::from(l.clone()))
		.collect();
	let paragraph = Paragraph::new(lines)
		.scroll((state.scroll, 0))
		.wrap(Wrap { trim: false });
	f.render_widget(paragraph, inner);
}

fn draw_confirm_pay(f: &mut Frame, area: Rect, state: &ConfirmPayState) {
	let popup = centered_rect(70, 45, area);
	f.render_widget(Clear, popup);
	let block = Block::default()
		.borders(Borders::ALL)
		.title("Confirm Invoice Payment (y: pay, n/Esc: cancel)");
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	let mut lines = vec![
		Line::from("This will pay the amount specified in the invoice from your wallet:"),
		Line::from(""),
		Line::from(vec![
			Span::raw("  Amount: "),
			Span::styled(
				format!("{} grin", state.amount),
				Style::default()
					.fg(Color::Yellow)
					.add_modifier(Modifier::BOLD),
			),
		]),
	];
	if !state.dest.is_empty() {
		lines.push(Line::from(format!("  Recipient: {}", state.dest)));
		lines.push(Line::from(""));
		lines.push(Line::from(
			"After confirmation the wallet will attempt to send the transaction",
		));
		lines.push(Line::from(
			"back to the invoicing party; if they are not listening, a slatepack",
		));
		lines.push(Line::from("will be produced for manual exchange."));
	} else {
		lines.push(Line::from(""));
		lines.push(Line::from(
			"A slatepack will be produced to send back to the invoice creator.",
		));
	}
	lines.push(Line::from(""));
	lines.push(Line::from(
		"Please review the amount carefully before proceeding.",
	));

	f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_context(f: &mut Frame, area: Rect, state: &ContextMenuState) {
	let height = (state.items.len() as u16 + 2).max(5);
	let popup = centered_rect(50, (height * 100 / area.height.max(1)).clamp(20, 60), area);
	f.render_widget(Clear, popup);
	let block = Block::default()
		.borders(Borders::ALL)
		.title(format!("{} (Enter: select, Esc: cancel)", state.title));
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	let items: Vec<ListItem> = state
		.items
		.iter()
		.map(|(label, _)| ListItem::new(label.clone()))
		.collect();
	let mut list_state = ListState::default();
	list_state.select(Some(state.selected));
	let list =
		List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
	f.render_stateful_widget(list, inner, &mut list_state);
}

fn draw_edit_setting(f: &mut Frame, area: Rect, state: &EditSettingState) {
	let popup = centered_rect(60, 25, area);
	f.render_widget(Clear, popup);
	let setting = &crate::tui::settings::SETTINGS[state.setting_idx];
	let block = Block::default()
		.borders(Borders::ALL)
		.title(format!("Edit: {} (Enter: save, Esc: cancel)", setting.label));
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	let rows = Layout::vertical([
		Constraint::Length(1),
		Constraint::Length(1),
		Constraint::Length(1),
	])
	.split(inner);

	f.render_widget(
		Paragraph::new(Line::from(vec![
			Span::raw("Value: "),
			Span::styled(
				state.field.value.clone(),
				Style::default().add_modifier(Modifier::BOLD),
			),
		])),
		rows[0],
	);
	f.render_widget(
		Paragraph::new(Line::from(Span::styled(
			setting.hint,
			Style::default().fg(Color::DarkGray),
		))),
		rows[1],
	);
	if let Some(err) = &state.error {
		f.render_widget(
			Paragraph::new(Line::from(Span::styled(
				err.clone(),
				Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
			))),
			rows[2],
		);
	}
}

fn draw_help(f: &mut Frame, area: Rect) {
	let popup = centered_rect(60, 70, area);
	f.render_widget(Clear, popup);
	let block = Block::default()
		.borders(Borders::ALL)
		.title("Help (any key to close)");
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	let lines = vec![
		Line::from("Global"),
		Line::from("  Tab / Up / Down     cycle menu tabs"),
		Line::from("  Enter               focus content / select"),
		Line::from("  Esc                 back to menu"),
		Line::from("  s                   toggle spent outputs"),
		Line::from("  ?                   this help"),
		Line::from("  q                   quit"),
		Line::from(""),
		Line::from("Tables"),
		Line::from("  j / k, arrows       move selection"),
		Line::from("  PgUp / PgDn         page selection"),
		Line::from("  Home / End          first / last row"),
		Line::from("  Enter               row actions (transactions, accounts,"),
		Line::from("                      settings)"),
		Line::from(""),
		Line::from("Forms"),
		Line::from("  Tab / Up / Down     move between fields"),
		Line::from("  Space / Enter       toggle checkboxes"),
		Line::from("  Enter (last field)  submit"),
		Line::from(""),
		Line::from("Output windows"),
		Line::from("  Up / Down           scroll"),
		Line::from("  c                   copy to clipboard"),
		Line::from("  q                   toggle QR view"),
	];
	f.render_widget(Paragraph::new(lines), inner);
}
