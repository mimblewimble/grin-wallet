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

/// Slatepack Output 'plugin' implementation
use std::fs::{metadata, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::libwallet::{slatepack, Error, Slate, Slatepack, SlatepackBin, Slatepacker};
use crate::{SlateGetter, SlatePutter};
use grin_wallet_util::byte_ser;

// And Slate putter impls to output to files
pub struct PathToSlatepack<'a> {
	pub pathbuf: PathBuf,
	pub packer: &'a Slatepacker<'a>,
	pub armor_output: bool,
}

impl<'a> PathToSlatepack<'a> {
	/// Create with pathbuf and recipients
	pub fn new(pathbuf: PathBuf, packer: &'a Slatepacker<'a>, armor_output: bool) -> Self {
		Self {
			pathbuf,
			packer,
			armor_output,
		}
	}

	pub fn get_slatepack_file_contents(&self) -> Result<Vec<u8>, Error> {
		let metadata = metadata(&self.pathbuf)?;
		let len = metadata.len();
		let min_len = slatepack::min_size();
		let max_len = slatepack::max_size();
		if len < min_len || len > max_len {
			let msg = format!(
				"Data is invalid length: {} | min: {}, max: {} |",
				len, min_len, max_len
			);
			return Err(Error::SlatepackDeser(msg));
		}
		let mut pub_tx_f = File::open(&self.pathbuf)?;
		let mut data = Vec::new();
		pub_tx_f.read_to_end(&mut data)?;
		Ok(data)
	}

	pub fn get_slatepack(&self, decrypt: bool) -> Result<Slatepack, Error> {
		let data = self.get_slatepack_file_contents()?;
		self.packer.deser_slatepack(&data, decrypt)
	}
}

impl<'a> SlatePutter for PathToSlatepack<'a> {
	fn put_tx(&self, slate: &Slate, as_bin: bool) -> Result<(), Error> {
		let slatepack = self.packer.create_slatepack(slate)?;
		let mut pub_tx = File::create(&self.pathbuf)?;
		if as_bin {
			if self.armor_output {
				let armored = self.packer.armor_slatepack(&slatepack)?;
				pub_tx.write_all(armored.as_bytes())?;
			} else {
				pub_tx.write_all(
					&byte_ser::to_bytes(&SlatepackBin(slatepack))
						.map_err(|_| Error::SlatepackSer)?,
				)?;
			}
		} else {
			pub_tx.write_all(
				serde_json::to_string_pretty(&slatepack)
					.map_err(|_| Error::SlateSer)?
					.as_bytes(),
			)?;
		}
		pub_tx.sync_all()?;
		Ok(())
	}
}

impl<'a> SlateGetter for PathToSlatepack<'a> {
	fn get_tx(&self) -> Result<(Slate, bool), Error> {
		let data = self.get_slatepack_file_contents()?;
		let slatepack = self.packer.deser_slatepack(&data, true)?;
		Ok((self.packer.get_slate(&slatepack)?, true))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	use grin_core::global;

	fn clean_output_dir(test_dir: &str) {
		let _ = remove_dir_all::remove_dir_all(test_dir);
	}

	fn setup(test_dir: &str) {
		clean_output_dir(test_dir);
	}

	const SLATEPACK_DIR: &'static str = "target/test_output/slatepack";

	#[test]
	fn pathbuf_get_file_contents() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		setup(SLATEPACK_DIR);

		fs::create_dir_all(SLATEPACK_DIR).unwrap();
		let sp_path = PathBuf::from(SLATEPACK_DIR).join("pack_file");

		// set Slatepack file to minimum allowable size
		{
			let f = File::create(sp_path.clone()).unwrap();
			f.set_len(slatepack::min_size()).unwrap();
		}

		let args = slatepack::SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		};
		let packer = Slatepacker::new(args);

		let mut pack_path = PathToSlatepack::new(sp_path.clone(), &packer, true);
		assert!(pack_path.get_slatepack_file_contents().is_ok());

		pack_path = PathToSlatepack::new(sp_path.clone(), &packer, false);
		assert!(pack_path.get_slatepack_file_contents().is_ok());

		// set Slatepack file to maximum allowable size
		{
			let f = File::create(sp_path.clone()).unwrap();
			f.set_len(slatepack::max_size()).unwrap();
		}

		pack_path = PathToSlatepack::new(sp_path.clone(), &packer, true);
		assert!(pack_path.get_slatepack_file_contents().is_ok());

		pack_path = PathToSlatepack::new(sp_path.clone(), &packer, false);
		assert!(pack_path.get_slatepack_file_contents().is_ok());

		// set Slatepack file below minimum allowable size
		{
			let f = File::create(sp_path.clone()).unwrap();
			f.set_len(slatepack::min_size() - 1).unwrap();
		}

		pack_path = PathToSlatepack::new(sp_path.clone(), &packer, true);
		assert!(pack_path.get_slatepack_file_contents().is_err());

		pack_path = PathToSlatepack::new(sp_path.clone(), &packer, false);
		assert!(pack_path.get_slatepack_file_contents().is_err());

		// set Slatepack file above maximum allowable size
		{
			let f = File::create(sp_path.clone()).unwrap();
			f.set_len(slatepack::max_size() + 1).unwrap();
		}

		pack_path = PathToSlatepack::new(sp_path.clone(), &packer, true);
		assert!(pack_path.get_slatepack_file_contents().is_err());

		pack_path = PathToSlatepack::new(sp_path.clone(), &packer, false);
		assert!(pack_path.get_slatepack_file_contents().is_err());
	}
}
