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

//! The Actions tab: a menu of every wallet subcommand, each backed by a
//! small form. Submitting a form builds the equivalent command-line
//! argument vector and hands it to the controller, which suspends the TUI
//! and runs it through the exact same `wallet_args::parse_and_execute`
//! dispatch used by plain CLI invocations - so every subcommand, including
//! its existing interactive prompts (password entry, slatepack pasting,
//! recovery phrase input, invoice confirmation), works unmodified.

use crate::tui::form::TextField;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

/// How a field's value should be appended to the synthetic command line.
#[derive(Copy, Clone)]
pub enum ArgKind {
	/// Appended as a bare positional argument (only if non-empty)
	Positional,
	/// Appended as `--<name> <value>` (only if non-empty)
	Opt(&'static str),
	/// Appended as `--<name>` if the field's boolean value is true
	Flag(&'static str),
}

pub struct FieldSpec {
	pub label: &'static str,
	pub arg: ArgKind,
	pub default: &'static str,
}

impl FieldSpec {
	pub const fn is_bool(&self) -> bool {
		matches!(self.arg, ArgKind::Flag(_))
	}
}

pub struct ActionSpec {
	pub subcommand: &'static str,
	pub title: &'static str,
	pub fields: &'static [FieldSpec],
}

macro_rules! field {
	($label:expr, Positional) => {
		FieldSpec {
			label: $label,
			arg: ArgKind::Positional,
			default: "",
		}
	};
	($label:expr, Opt($name:expr)) => {
		FieldSpec {
			label: $label,
			arg: ArgKind::Opt($name),
			default: "",
		}
	};
	($label:expr, Opt($name:expr), $default:expr) => {
		FieldSpec {
			label: $label,
			arg: ArgKind::Opt($name),
			default: $default,
		}
	};
	($label:expr, Flag($name:expr)) => {
		FieldSpec {
			label: $label,
			arg: ArgKind::Flag($name),
			default: "false",
		}
	};
}

pub static ACTIONS: &[ActionSpec] = &[
	ActionSpec {
		subcommand: "send",
		title: "Send",
		fields: &[
			field!("Amount (or 'max')", Positional),
			field!("Destination address", Opt("dest")),
			field!("Min confirmations", Opt("min_conf"), "10"),
			field!("Selection (smallest/all)", Opt("selection"), "smallest"),
			field!("Change outputs", Opt("change_outputs"), "1"),
			field!("TTL blocks (optional)", Opt("ttl_blocks")),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
			field!("No payment proof", Flag("no_payment_proof")),
			field!("Manual (don't try Tor)", Flag("manual")),
			field!("Amount includes fee", Flag("amount_includes_fee")),
			field!("Output file (optional)", Opt("outfile")),
		],
	},
	ActionSpec {
		subcommand: "receive",
		title: "Receive",
		fields: &[
			field!("Input slatepack file (blank = paste)", Opt("input")),
			field!("Manual (don't try Tor)", Flag("manual")),
			field!("Output file (optional)", Opt("outfile")),
		],
	},
	ActionSpec {
		subcommand: "unpack",
		title: "Unpack / Inspect Slatepack",
		fields: &[field!("Input slatepack file (blank = paste)", Opt("input"))],
	},
	ActionSpec {
		subcommand: "finalize",
		title: "Finalize",
		fields: &[
			field!("Input slatepack file (blank = paste)", Opt("input")),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
			field!("Don't post transaction", Flag("nopost")),
			field!("Output file (optional)", Opt("outfile")),
		],
	},
	ActionSpec {
		subcommand: "invoice",
		title: "Issue Invoice",
		fields: &[
			field!("Amount", Positional),
			field!("Destination address", Opt("dest"), "default"),
			field!("Output file (optional)", Opt("outfile")),
		],
	},
	ActionSpec {
		subcommand: "pay",
		title: "Pay Invoice",
		fields: &[
			field!("Input slatepack file (blank = paste)", Opt("input")),
			field!("Destination override (optional)", Opt("dest")),
			field!("Min confirmations", Opt("min_conf"), "10"),
			field!("Selection (smallest/all)", Opt("selection"), "smallest"),
			field!("TTL blocks (optional)", Opt("ttl_blocks")),
			field!("Manual (don't try Tor)", Flag("manual")),
			field!("Output file (optional)", Opt("outfile")),
		],
	},
	ActionSpec {
		subcommand: "post",
		title: "Post Transaction",
		fields: &[
			field!("Input slatepack file (blank = paste)", Opt("input")),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
		],
	},
	ActionSpec {
		subcommand: "repost",
		title: "Repost Transaction",
		fields: &[
			field!("Transaction ID", Opt("id")),
			field!("Dump to file instead (optional)", Opt("dumpfile")),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
		],
	},
	ActionSpec {
		subcommand: "cancel",
		title: "Cancel Transaction",
		fields: &[
			field!("Transaction ID", Opt("id")),
			field!("Transaction Slate UUID", Opt("txid")),
		],
	},
	ActionSpec {
		subcommand: "account",
		title: "Create Account",
		fields: &[field!("New account name", Opt("create"))],
	},
	ActionSpec {
		subcommand: "export_proof",
		title: "Export Payment Proof",
		fields: &[
			field!("Output proof file", Positional),
			field!("Transaction ID", Opt("id")),
			field!("Transaction Slate UUID", Opt("txid")),
		],
	},
	ActionSpec {
		subcommand: "verify_proof",
		title: "Verify Payment Proof",
		fields: &[field!("Proof file", Positional)],
	},
	ActionSpec {
		subcommand: "address",
		title: "Show Slatepack Address",
		fields: &[],
	},
	ActionSpec {
		subcommand: "scan",
		title: "Rescan Wallet Outputs",
		fields: &[
			field!("Start height (optional)", Opt("start_height")),
			field!("Blocks back from tip (optional)", Opt("backwards_from_tip")),
			field!("Delete unconfirmed", Flag("delete_unconfirmed")),
		],
	},
	ActionSpec {
		subcommand: "rewind_hash",
		title: "Show Rewind Hash",
		fields: &[],
	},
	ActionSpec {
		subcommand: "scan_rewind_hash",
		title: "Scan View Wallet (Rewind Hash)",
		fields: &[
			field!("Rewind hash", Positional),
			field!("Start height (optional)", Opt("start_height")),
			field!("Blocks back from tip (optional)", Opt("backwards_from_tip")),
		],
	},
	ActionSpec {
		subcommand: "listen",
		title: "Start Listener",
		fields: &[
			field!("Port (optional)", Opt("port")),
			field!("No Tor listener", Flag("no_tor")),
			field!("Tor bridge line (optional)", Opt("bridge")),
		],
	},
	ActionSpec {
		subcommand: "owner_api",
		title: "Start Owner API (blocks until Ctrl+C)",
		fields: &[
			field!("Port (optional)", Opt("port")),
			field!("Also run Foreign API", Flag("run_foreign")),
		],
	},
	ActionSpec {
		subcommand: "recover",
		title: "Show Recovery Phrase",
		fields: &[],
	},
	ActionSpec {
		subcommand: "open",
		title: "Open / Unlock Wallet",
		fields: &[],
	},
	ActionSpec {
		subcommand: "close",
		title: "Close / Lock Wallet",
		fields: &[],
	},
];

pub enum FieldValue {
	Text(TextField),
	Bool(bool),
}

pub struct FormState {
	pub spec_idx: usize,
	pub values: Vec<FieldValue>,
	pub focus: usize,
}

impl FormState {
	pub fn new(spec_idx: usize) -> FormState {
		let spec = &ACTIONS[spec_idx];
		let values = spec
			.fields
			.iter()
			.map(|f| {
				if f.is_bool() {
					FieldValue::Bool(f.default == "true")
				} else {
					FieldValue::Text(TextField::new(f.default))
				}
			})
			.collect();
		FormState {
			spec_idx,
			values,
			focus: 0,
		}
	}

	pub fn spec(&self) -> &'static ActionSpec {
		&ACTIONS[self.spec_idx]
	}

	pub fn field_count(&self) -> usize {
		self.values.len()
	}

	pub fn next_field(&mut self) {
		if self.field_count() > 0 {
			self.focus = (self.focus + 1) % self.field_count();
		}
	}

	pub fn prev_field(&mut self) {
		let len = self.field_count();
		if len > 0 {
			self.focus = (self.focus + len - 1) % len;
		}
	}

	pub fn toggle_focused(&mut self) {
		if let Some(FieldValue::Bool(b)) = self.values.get_mut(self.focus) {
			*b = !*b;
		}
	}

	fn focused_text(&mut self) -> Option<&mut TextField> {
		match self.values.get_mut(self.focus) {
			Some(FieldValue::Text(t)) => Some(t),
			_ => None,
		}
	}

	pub fn insert(&mut self, c: char) {
		if let Some(t) = self.focused_text() {
			t.insert(c);
		}
	}

	pub fn backspace(&mut self) {
		if let Some(t) = self.focused_text() {
			t.backspace();
		}
	}

	pub fn delete(&mut self) {
		if let Some(t) = self.focused_text() {
			t.delete();
		}
	}

	pub fn left(&mut self) {
		if let Some(t) = self.focused_text() {
			t.left();
		}
	}

	pub fn right(&mut self) {
		if let Some(t) = self.focused_text() {
			t.right();
		}
	}

	pub fn home(&mut self) {
		if let Some(t) = self.focused_text() {
			t.home();
		}
	}

	pub fn end(&mut self) {
		if let Some(t) = self.focused_text() {
			t.end();
		}
	}

	/// Build the `grin-wallet <subcommand> ...` argv this form represents.
	pub fn build_argv(&self) -> Vec<String> {
		let spec = self.spec();
		let mut argv = vec!["grin-wallet".to_string(), spec.subcommand.to_string()];

		// Positional arguments first, in field order
		for (field, value) in spec.fields.iter().zip(self.values.iter()) {
			if let (ArgKind::Positional, FieldValue::Text(t)) = (field.arg, value) {
				if !t.value.trim().is_empty() {
					argv.push(t.value.trim().to_string());
				}
			}
		}

		for (field, value) in spec.fields.iter().zip(self.values.iter()) {
			match (field.arg, value) {
				(ArgKind::Opt(name), FieldValue::Text(t)) => {
					if !t.value.trim().is_empty() {
						argv.push(format!("--{}", name));
						argv.push(t.value.trim().to_string());
					}
				}
				(ArgKind::Flag(name), FieldValue::Bool(true)) => {
					argv.push(format!("--{}", name));
				}
				_ => {}
			}
		}

		argv
	}
}

pub enum Modal {
	Form(FormState),
}

/// Draw the list of available actions (shown when no modal is active)
pub fn draw(f: &mut Frame, area: Rect, list_state: &mut ListState) {
	let items: Vec<ListItem> = ACTIONS
		.iter()
		.map(|a| ListItem::new(format!("{}  ({})", a.title, a.subcommand)))
		.collect();

	let list = List::new(items)
		.block(
			Block::default()
				.borders(Borders::ALL)
				.title("Actions - Enter to run, all wallet commands are supported"),
		)
		.highlight_style(Style::default().add_modifier(Modifier::REVERSED));

	f.render_stateful_widget(list, area, list_state);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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

/// Draw the form modal for the action currently being configured
pub fn draw_form(f: &mut Frame, area: Rect, form: &FormState) {
	let popup = centered_rect(70, 70.min(20 + form.field_count() as u16 * 4), area);
	f.render_widget(Clear, popup);

	let spec = form.spec();
	let block = Block::default()
		.borders(Borders::ALL)
		.title(format!("{} (Enter: next/submit, Esc: cancel)", spec.title));
	let inner = block.inner(popup);
	f.render_widget(block, popup);

	if spec.fields.is_empty() {
		let text = Paragraph::new("No parameters needed - press Enter to run.");
		f.render_widget(text, inner);
		return;
	}

	let rows = Layout::vertical(
		spec.fields
			.iter()
			.map(|_| Constraint::Length(2))
			.collect::<Vec<_>>(),
	)
	.split(inner);

	for (i, (field, value)) in spec.fields.iter().zip(form.values.iter()).enumerate() {
		let focused = i == form.focus;
		let label_style = if focused {
			Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
		} else {
			Style::default()
		};
		let value_str = match value {
			FieldValue::Text(t) => t.value.clone(),
			FieldValue::Bool(b) => {
				if *b {
					"[x]".to_string()
				} else {
					"[ ]".to_string()
				}
			}
		};
		let line = Line::from(vec![
			Span::styled(format!("{:<28}", field.label), label_style),
			Span::raw(value_str),
		]);
		f.render_widget(Paragraph::new(line), rows[i]);
	}
}
