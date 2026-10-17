// Copyright 2021 The Grin Developers
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

//! Functions and types for handling Slatepack transactions

mod address;
mod armor;
mod types;

pub use self::address::SlatepackAddress;
pub use self::armor::{max_size, min_size, SlatepackArmor, FOOTER, HEADER};
pub use self::types::{Slatepack, SlatepackAddressIndex, SlatepackBin, SlatepackMode};

use std::fs::{metadata, File};
use std::io::Read;
use std::path::PathBuf;

/// Get slatepack file contents.
pub fn get_slatepack_file_contents(path: &PathBuf) -> Result<Vec<u8>, crate::Error> {
	let metadata = metadata(path)?;
	let len = metadata.len();
	let min_len = min_size();
	let max_len = max_size();
	if len < min_len || len > max_len {
		let msg = format!(
			"Data is invalid length: {} | min: {}, max: {} |",
			len, min_len, max_len
		);
		return Err(crate::Error::SlatepackDeser(msg));
	}
	let mut pub_tx_f = File::open(path)?;
	let mut data = Vec::new();
	pub_tx_f.read_to_end(&mut data)?;
	Ok(data)
}
