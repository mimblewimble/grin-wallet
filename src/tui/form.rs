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

//! A minimal single-line, cursor-editable text field used by Action forms.

/// A single-line editable text buffer with a cursor position, measured in
/// characters (not bytes) so editing behaves correctly with multi-byte input.
#[derive(Clone, Debug, Default)]
pub struct TextField {
	pub value: String,
	pub cursor: usize,
}

impl TextField {
	pub fn new(default: &str) -> TextField {
		let cursor = default.chars().count();
		TextField {
			value: default.to_string(),
			cursor,
		}
	}

	fn chars(&self) -> Vec<char> {
		self.value.chars().collect()
	}

	pub fn insert(&mut self, c: char) {
		let mut chars = self.chars();
		chars.insert(self.cursor, c);
		self.value = chars.into_iter().collect();
		self.cursor += 1;
	}

	pub fn backspace(&mut self) {
		if self.cursor == 0 {
			return;
		}
		let mut chars = self.chars();
		chars.remove(self.cursor - 1);
		self.value = chars.into_iter().collect();
		self.cursor -= 1;
	}

	pub fn delete(&mut self) {
		let mut chars = self.chars();
		if self.cursor >= chars.len() {
			return;
		}
		chars.remove(self.cursor);
		self.value = chars.into_iter().collect();
	}

	pub fn left(&mut self) {
		if self.cursor > 0 {
			self.cursor -= 1;
		}
	}

	pub fn right(&mut self) {
		if self.cursor < self.chars().len() {
			self.cursor += 1;
		}
	}

	pub fn home(&mut self) {
		self.cursor = 0;
	}

	pub fn end(&mut self) {
		self.cursor = self.chars().len();
	}

	/// Insert pasted text at the cursor, flattening newlines to spaces
	/// (fields are single-line).
	pub fn paste(&mut self, s: &str) {
		for c in s.chars() {
			match c {
				'\n' | '\r' => self.insert(' '),
				c if c.is_control() => {}
				c => self.insert(c),
			}
		}
	}
}
