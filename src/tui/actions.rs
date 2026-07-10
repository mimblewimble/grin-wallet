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
//! small validated form. All actions run inside the TUI — either on a
//! background worker thread or (for open/close/recover) via an in-TUI
//! password modal / direct Owner API call. The alternate screen is never
//! left while the dashboard is up.

use crate::tui::form::TextField;
use grin_core::core::amount_from_hr_string;
use grin_wallet_libwallet::SlatepackAddress;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use std::convert::TryFrom;
use std::path::Path;
use uuid::Uuid;

/// How a field's value maps to a CLI-style argument name (used for looking
/// fields up by name and for the pure `build_argv` unit tests).
#[derive(Copy, Clone, PartialEq)]
pub enum ArgKind {
	/// Appended as a bare positional argument (only if non-empty)
	Positional,
	/// Appended as `--<name> <value>` (only if non-empty)
	Opt(&'static str),
	/// Appended as `--<name>` if the field's boolean value is true
	Flag(&'static str),
}

/// Per-field validation applied when the form is submitted
#[derive(Copy, Clone, PartialEq)]
pub enum Validate {
	None,
	/// Required decimal grin amount
	Amount,
	/// Required decimal grin amount, or the literal "max"
	AmountOrMax,
	/// Required whole number
	U64,
	/// Optional whole number
	U64Opt,
	/// Optional slatepack address (http URLs also tolerated for legacy sends)
	AddressOpt,
	/// Optional path that must point to an existing file when set
	FileOpt,
	/// Required path to an existing file
	FileReq,
	/// Optional UUID
	UuidOpt,
	/// Required non-empty value
	Required,
}

pub struct FieldSpec {
	pub label: &'static str,
	pub arg: ArgKind,
	pub default: &'static str,
	pub validate: Validate,
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
	/// Optional cross-field check run after per-field validation
	pub check: Option<fn(&FormState) -> Result<(), String>>,
}

macro_rules! field {
	($label:expr, Positional, $validate:ident) => {
		FieldSpec {
			label: $label,
			arg: ArgKind::Positional,
			default: "",
			validate: Validate::$validate,
		}
	};
	($label:expr, Opt($name:expr), $default:expr, $validate:ident) => {
		FieldSpec {
			label: $label,
			arg: ArgKind::Opt($name),
			default: $default,
			validate: Validate::$validate,
		}
	};
	($label:expr, Flag($name:expr)) => {
		FieldSpec {
			label: $label,
			arg: ArgKind::Flag($name),
			default: "false",
			validate: Validate::None,
		}
	};
}

fn check_one_of_id_txid(form: &FormState) -> Result<(), String> {
	if form.text("id").is_empty() == form.text("txid").is_empty() {
		Err("Provide exactly one of transaction ID or slate UUID".to_string())
	} else {
		Ok(())
	}
}

fn check_height_args(form: &FormState) -> Result<(), String> {
	if !form.text("start_height").is_empty() && !form.text("backwards_from_tip").is_empty() {
		Err("Start height and blocks-back-from-tip cannot both be set".to_string())
	} else {
		Ok(())
	}
}

pub static ACTIONS: &[ActionSpec] = &[
	ActionSpec {
		subcommand: "send",
		title: "Send",
		check: None,
		fields: &[
			field!("Amount (or 'max')", Positional, AmountOrMax),
			field!("Destination address", Opt("dest"), "", AddressOpt),
			field!("Min confirmations", Opt("min_conf"), "10", U64),
			field!("Use 'all' coin selection", Flag("selection_all")),
			field!("Change outputs", Opt("change_outputs"), "1", U64),
			field!("TTL blocks (optional)", Opt("ttl_blocks"), "", U64Opt),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
			field!("No payment proof", Flag("no_payment_proof")),
			field!("Manual (don't try Tor)", Flag("manual")),
			field!("Amount includes fee", Flag("amount_includes_fee")),
			field!("Estimate fee only", Flag("estimate")),
			field!("Output file (optional)", Opt("outfile"), "", None),
		],
	},
	ActionSpec {
		subcommand: "receive",
		title: "Receive",
		check: None,
		fields: &[
			field!("Input file (blank to paste)", Opt("input"), "", FileOpt),
			field!("Manual (don't try Tor)", Flag("manual")),
			field!("Output file (optional)", Opt("outfile"), "", None),
		],
	},
	ActionSpec {
		subcommand: "unpack",
		title: "Unpack / Inspect Slatepack",
		check: None,
		fields: &[field!("Input file (blank to paste)", Opt("input"), "", FileOpt)],
	},
	ActionSpec {
		subcommand: "finalize",
		title: "Finalize",
		check: None,
		fields: &[
			field!("Input file (blank to paste)", Opt("input"), "", FileOpt),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
			field!("Don't post transaction", Flag("nopost")),
			field!("Output file (optional)", Opt("outfile"), "", None),
		],
	},
	ActionSpec {
		subcommand: "invoice",
		title: "Issue Invoice",
		check: None,
		fields: &[
			field!("Amount", Positional, Amount),
			field!("Encrypt for address (optional)", Opt("dest"), "", AddressOpt),
			field!("Output file (optional)", Opt("outfile"), "", None),
		],
	},
	ActionSpec {
		subcommand: "pay",
		title: "Pay Invoice",
		check: None,
		fields: &[
			field!("Input file (blank to paste)", Opt("input"), "", FileOpt),
			field!("Destination override (optional)", Opt("dest"), "", AddressOpt),
			field!("Min confirmations", Opt("min_conf"), "10", U64),
			field!("Use 'all' coin selection", Flag("selection_all")),
			field!("TTL blocks (optional)", Opt("ttl_blocks"), "", U64Opt),
			field!("Manual (don't try Tor)", Flag("manual")),
			field!("Output file (optional)", Opt("outfile"), "", None),
		],
	},
	ActionSpec {
		subcommand: "post",
		title: "Post Transaction",
		check: None,
		fields: &[
			field!("Input file (blank to paste)", Opt("input"), "", FileOpt),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
		],
	},
	ActionSpec {
		subcommand: "repost",
		title: "Repost Transaction",
		check: None,
		fields: &[
			field!("Transaction ID", Opt("id"), "", U64),
			field!("Dump to file instead (optional)", Opt("dumpfile"), "", None),
			field!("Fluff (skip Dandelion)", Flag("fluff")),
		],
	},
	ActionSpec {
		subcommand: "cancel",
		title: "Cancel Transaction",
		check: Some(check_one_of_id_txid),
		fields: &[
			field!("Transaction ID", Opt("id"), "", U64Opt),
			field!("Transaction Slate UUID", Opt("txid"), "", UuidOpt),
		],
	},
	ActionSpec {
		subcommand: "account",
		title: "Create Account",
		check: None,
		fields: &[field!("New account name", Opt("create"), "", Required)],
	},
	ActionSpec {
		subcommand: "export_proof",
		title: "Export Payment Proof",
		check: Some(check_one_of_id_txid),
		fields: &[
			field!("Output proof file", Positional, Required),
			field!("Transaction ID", Opt("id"), "", U64Opt),
			field!("Transaction Slate UUID", Opt("txid"), "", UuidOpt),
		],
	},
	ActionSpec {
		subcommand: "verify_proof",
		title: "Verify Payment Proof",
		check: None,
		fields: &[field!("Proof file", Positional, FileReq)],
	},
	ActionSpec {
		subcommand: "address",
		title: "Show Slatepack Address",
		check: None,
		fields: &[],
	},
	ActionSpec {
		subcommand: "scan",
		title: "Rescan Wallet Outputs",
		check: Some(check_height_args),
		fields: &[
			field!("Start height (optional)", Opt("start_height"), "", U64Opt),
			field!(
				"Blocks back from tip (optional)",
				Opt("backwards_from_tip"),
				"",
				U64Opt
			),
			field!("Delete unconfirmed", Flag("delete_unconfirmed")),
		],
	},
	ActionSpec {
		subcommand: "rewind_hash",
		title: "Show Rewind Hash",
		check: None,
		fields: &[],
	},
	ActionSpec {
		subcommand: "scan_rewind_hash",
		title: "Scan View Wallet (Rewind Hash)",
		check: Some(check_height_args),
		fields: &[
			field!("Rewind hash", Positional, Required),
			field!("Start height (optional)", Opt("start_height"), "", U64Opt),
			field!(
				"Blocks back from tip (optional)",
				Opt("backwards_from_tip"),
				"",
				U64Opt
			),
		],
	},
	ActionSpec {
		subcommand: "listen",
		title: "Start Listener (background)",
		check: None,
		fields: &[
			field!("Port (optional)", Opt("port"), "", U64Opt),
			field!("No Tor listener", Flag("no_tor")),
			field!("Tor bridge line (optional)", Opt("bridge"), "", None),
		],
	},
	ActionSpec {
		subcommand: "owner_api",
		title: "Start Owner API (background)",
		check: None,
		fields: &[
			field!("Port (optional)", Opt("port"), "", U64Opt),
			field!("Also run Foreign API", Flag("run_foreign")),
		],
	},
	ActionSpec {
		subcommand: "recover",
		title: "Show Recovery Phrase",
		check: None,
		fields: &[],
	},
	ActionSpec {
		subcommand: "open",
		title: "Open / Unlock Wallet",
		check: None,
		fields: &[],
	},
	ActionSpec {
		subcommand: "close",
		title: "Close / Lock Wallet",
		check: None,
		fields: &[],
	},
];

/// Index of the action with the given subcommand name
pub fn action_index(subcommand: &str) -> Option<usize> {
	ACTIONS.iter().position(|a| a.subcommand == subcommand)
}

pub enum FieldValue {
	Text(TextField),
	Bool(bool),
}

pub struct FormState {
	pub spec_idx: usize,
	pub values: Vec<FieldValue>,
	pub focus: usize,
	pub error: Option<String>,
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
			error: None,
		}
	}

	/// Set the value of the `--<name>` field, e.g. to pre-fill a
	/// transaction id from a context menu
	pub fn prefill(mut self, name: &str, value: &str) -> FormState {
		let spec = self.spec();
		for (i, f) in spec.fields.iter().enumerate() {
			if matches!(f.arg, ArgKind::Opt(n) if n == name) {
				self.values[i] = FieldValue::Text(TextField::new(value));
			}
		}
		self
	}

	pub fn spec(&self) -> &'static ActionSpec {
		&ACTIONS[self.spec_idx]
	}

	pub fn field_count(&self) -> usize {
		self.values.len()
	}

	/// Trimmed value of the `--<name>` text field ("" if absent)
	pub fn text(&self, name: &str) -> String {
		let spec = self.spec();
		for (f, v) in spec.fields.iter().zip(self.values.iter()) {
			if matches!(f.arg, ArgKind::Opt(n) if n == name) {
				if let FieldValue::Text(t) = v {
					return t.value.trim().to_string();
				}
			}
		}
		String::new()
	}

	/// Trimmed value of the nth positional field ("" if absent)
	pub fn positional(&self, idx: usize) -> String {
		let spec = self.spec();
		let mut seen = 0;
		for (f, v) in spec.fields.iter().zip(self.values.iter()) {
			if f.arg == ArgKind::Positional {
				if seen == idx {
					if let FieldValue::Text(t) = v {
						return t.value.trim().to_string();
					}
				}
				seen += 1;
			}
		}
		String::new()
	}

	/// Value of the `--<name>` flag field (false if absent)
	pub fn flag(&self, name: &str) -> bool {
		let spec = self.spec();
		for (f, v) in spec.fields.iter().zip(self.values.iter()) {
			if matches!(f.arg, ArgKind::Flag(n) if n == name) {
				if let FieldValue::Bool(b) = v {
					return *b;
				}
			}
		}
		false
	}

	/// `text(name)` as Some(value) when non-empty
	pub fn text_opt(&self, name: &str) -> Option<String> {
		let v = self.text(name);
		if v.is_empty() {
			None
		} else {
			Some(v)
		}
	}

	/// Optional u64 value of the `--<name>` field (validated beforehand)
	pub fn u64_opt(&self, name: &str) -> Option<u64> {
		self.text(name).parse().ok()
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

	pub fn focused_is_bool(&self) -> bool {
		matches!(self.values.get(self.focus), Some(FieldValue::Bool(_)))
	}

	pub fn focused_text(&mut self) -> Option<&mut TextField> {
		match self.values.get_mut(self.focus) {
			Some(FieldValue::Text(t)) => Some(t),
			_ => None,
		}
	}

	/// Validate all fields plus the spec's cross-field check
	pub fn validate(&self) -> Result<(), String> {
		let spec = self.spec();
		for (f, v) in spec.fields.iter().zip(self.values.iter()) {
			if let FieldValue::Text(t) = v {
				validate_field(f, &t.value)?;
			}
		}
		if let Some(check) = spec.check {
			check(self)?;
		}
		Ok(())
	}

	/// Build the `grin-wallet <subcommand> ...` argv this form represents
	/// (kept for unit tests of field → argument mapping).
	#[cfg(test)]
	pub fn build_argv(&self) -> Vec<String> {
		let spec = self.spec();
		let mut argv = vec!["grin-wallet".to_string(), spec.subcommand.to_string()];

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

fn validate_field(f: &FieldSpec, value: &str) -> Result<(), String> {
	let v = value.trim();
	match f.validate {
		Validate::None => Ok(()),
		Validate::Amount => match amount_from_hr_string(v) {
			Ok(a) if !v.is_empty() && a > 0 => Ok(()),
			_ => Err(format!("'{}' must be a valid grin amount", f.label)),
		},
		Validate::AmountOrMax => {
			if v == "max" {
				Ok(())
			} else {
				match amount_from_hr_string(v) {
					Ok(a) if !v.is_empty() && a > 0 => Ok(()),
					_ => Err(format!("'{}' must be a valid grin amount or 'max'", f.label)),
				}
			}
		}
		Validate::U64 => match v.parse::<u64>() {
			Ok(_) => Ok(()),
			Err(_) => Err(format!("'{}' must be a whole number", f.label)),
		},
		Validate::U64Opt => {
			if v.is_empty() {
				Ok(())
			} else {
				match v.parse::<u64>() {
					Ok(_) => Ok(()),
					Err(_) => Err(format!("'{}' must be a whole number", f.label)),
				}
			}
		}
		Validate::AddressOpt => {
			if v.is_empty() || v.starts_with("http") {
				Ok(())
			} else {
				match SlatepackAddress::try_from(v) {
					Ok(_) => Ok(()),
					Err(_) => Err(format!("'{}' is not a valid slatepack address", f.label)),
				}
			}
		}
		Validate::FileOpt => {
			if v.is_empty() || Path::new(v).is_file() {
				Ok(())
			} else {
				Err(format!("'{}': file not found: {}", f.label, v))
			}
		}
		Validate::FileReq => {
			if !v.is_empty() && Path::new(v).is_file() {
				Ok(())
			} else {
				Err(format!("'{}' must be an existing file", f.label))
			}
		}
		Validate::UuidOpt => {
			if v.is_empty() {
				Ok(())
			} else {
				match Uuid::parse_str(v) {
					Ok(_) => Ok(()),
					Err(_) => Err(format!("'{}' must be a valid UUID", f.label)),
				}
			}
		}
		Validate::Required => {
			if v.is_empty() {
				Err(format!("'{}' is required", f.label))
			} else {
				Ok(())
			}
		}
	}
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
				.title("Actions - Enter to run"),
		)
		.highlight_style(Style::default().add_modifier(Modifier::REVERSED));

	f.render_stateful_widget(list, area, list_state);
}

/// Draw the form modal for the action currently being configured
pub fn draw_form(f: &mut Frame, area: Rect, form: &FormState) {
	let popup = crate::tui::modals::centered_rect(70, 70.min(20 + form.field_count() as u16 * 4), area);
	f.render_widget(ratatui::widgets::Clear, popup);

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

	let mut constraints: Vec<Constraint> =
		spec.fields.iter().map(|_| Constraint::Length(2)).collect();
	constraints.push(Constraint::Length(2));
	let rows = Layout::vertical(constraints).split(inner);

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
			Span::styled(format!("{:<32}", field.label), label_style),
			Span::raw(value_str),
		]);
		f.render_widget(Paragraph::new(line), rows[i]);
	}

	if let Some(err) = &form.error {
		let line = Line::from(Span::styled(
			err.clone(),
			Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
		));
		f.render_widget(Paragraph::new(line), rows[spec.fields.len()]);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn build_argv_positional_opts_and_flags() {
		let idx = action_index("send").unwrap();
		let mut form = FormState::new(idx)
			.prefill("dest", "tgrin1abc")
			.prefill("ttl_blocks", "12");
		// amount is the first (positional) field
		form.values[0] = FieldValue::Text(TextField::new("1.5"));
		// set the fluff flag
		let fluff_idx = ACTIONS[idx]
			.fields
			.iter()
			.position(|f| f.arg == ArgKind::Flag("fluff"))
			.unwrap();
		form.values[fluff_idx] = FieldValue::Bool(true);

		let argv = form.build_argv();
		assert_eq!(argv[0], "grin-wallet");
		assert_eq!(argv[1], "send");
		// positional comes right after the subcommand
		assert_eq!(argv[2], "1.5");
		let joined = argv.join(" ");
		assert!(joined.contains("--dest tgrin1abc"));
		assert!(joined.contains("--ttl_blocks 12"));
		assert!(joined.contains("--fluff"));
		// defaults are still emitted
		assert!(joined.contains("--min_conf 10"));
		// empty optional fields are not
		assert!(!joined.contains("--outfile"));
	}

	#[test]
	fn form_value_getters() {
		let idx = action_index("send").unwrap();
		let mut form = FormState::new(idx).prefill("dest", "abc");
		form.values[0] = FieldValue::Text(TextField::new(" max "));
		assert_eq!(form.positional(0), "max");
		assert_eq!(form.text("dest"), "abc");
		assert_eq!(form.text("outfile"), "");
		assert_eq!(form.text_opt("outfile"), None);
		assert_eq!(form.u64_opt("min_conf"), Some(10));
		assert!(!form.flag("fluff"));
	}

	#[test]
	fn validate_amount_and_numbers() {
		let idx = action_index("send").unwrap();
		let mut form = FormState::new(idx);
		// empty amount fails
		assert!(form.validate().is_err());
		form.values[0] = FieldValue::Text(TextField::new("nonsense"));
		assert!(form.validate().is_err());
		form.values[0] = FieldValue::Text(TextField::new("max"));
		assert!(form.validate().is_ok());
		form.values[0] = FieldValue::Text(TextField::new("1.234"));
		assert!(form.validate().is_ok());
	}

	#[test]
	fn validate_cancel_requires_exactly_one_id() {
		let idx = action_index("cancel").unwrap();
		// neither set
		assert!(FormState::new(idx).validate().is_err());
		// only numeric id
		assert!(FormState::new(idx).prefill("id", "3").validate().is_ok());
		// only uuid
		assert!(FormState::new(idx)
			.prefill("txid", "0436430c-2b02-624c-2032-570501212b00")
			.validate()
			.is_ok());
		// bad uuid
		assert!(FormState::new(idx)
			.prefill("txid", "not-a-uuid")
			.validate()
			.is_err());
		// both set
		assert!(FormState::new(idx)
			.prefill("id", "3")
			.prefill("txid", "0436430c-2b02-624c-2032-570501212b00")
			.validate()
			.is_err());
	}

	#[test]
	fn validate_height_exclusivity() {
		let idx = action_index("scan").unwrap();
		assert!(FormState::new(idx).validate().is_ok());
		assert!(FormState::new(idx)
			.prefill("start_height", "100")
			.validate()
			.is_ok());
		assert!(FormState::new(idx)
			.prefill("start_height", "100")
			.prefill("backwards_from_tip", "50")
			.validate()
			.is_err());
	}
}
