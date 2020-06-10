// Copyright 2020 The Grin Developers
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

use std::convert::TryFrom;
use std::iter::FromIterator;

use crate::{Error, ErrorKind};
use crate::{
	Slate, SlateVersion, Slatepack, SlatepackAddress, SlatepackArmor, SlatepackBin,
	VersionedBinSlate, VersionedSlate,
};

use grin_wallet_util::byte_ser;

use ed25519_dalek::SecretKey as edSecretKey;

#[derive(Clone)]
/// Arguments, mostly for encrypting decrypting a slatepack
pub struct SlatepackerArgs<'a> {
	/// Optional sender to include in slatepack
	pub sender: Option<SlatepackAddress>,
	/// Optional list of recipients, for encryption
	pub recipients: Vec<SlatepackAddress>,
	/// Optional decryption key
	pub dec_key: Option<&'a edSecretKey>,
}

/// Helper struct to pack and unpack slatepacks
#[derive(Clone)]
pub struct Slatepacker<'a>(SlatepackerArgs<'a>);

impl<'a> Slatepacker<'a> {
	/// Create with pathbuf and recipients
	pub fn new(args: SlatepackerArgs<'a>) -> Self {
		Self(args)
	}

	/// return slatepack
	pub fn deser_slatepack(&self, data: Vec<u8>, decrypt: bool) -> Result<Slatepack, Error> {
		// check if data is armored, if so, remove and continue
		if data.len() < super::armor::HEADER.len() {
			let msg = format!("Data too short");
			return Err(ErrorKind::SlatepackDeser(msg).into());
		}
		let test_header = Vec::from_iter(data[0..super::armor::HEADER.len()].iter().cloned());
		let data = match String::from_utf8(test_header) {
			Ok(s) => {
				if s.as_str() == super::armor::HEADER {
					SlatepackArmor::decode(
						String::from_utf8(data)
							.map_err(|e| {
								let msg = format!("{}", e);
								error!("Error decoding slatepack armor: {}", msg);
								ErrorKind::SlatepackDeser(msg)
							})?
							.as_str(),
					)?
				} else {
					data
				}
			}
			Err(_) => data,
		};

		// try as bin first, then as json
		let mut slatepack = match byte_ser::from_bytes::<SlatepackBin>(&data) {
			Ok(s) => s.0,
			Err(e) => {
				debug!("Not a valid binary slatepack: {} - Will try JSON", e);
				let content = String::from_utf8(data).map_err(|e| {
					let msg = format!("{}", e);
					ErrorKind::SlatepackDeser(msg)
				})?;
				serde_json::from_str(&content).map_err(|e| {
					let msg = format!("Error reading JSON slatepack: {}", e);
					ErrorKind::SlatepackDeser(msg)
				})?
			}
		};

		slatepack.ver_check_warn();
		if decrypt {
			slatepack.try_decrypt_payload(self.0.dec_key)?;
		}
		Ok(slatepack)
	}

	/// Create slatepack from slate and args
	pub fn create_slatepack(&self, slate: &Slate) -> Result<Slatepack, Error> {
		let out_slate = VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?;
		let bin_slate =
			VersionedBinSlate::try_from(out_slate).map_err(|_| ErrorKind::SlatepackSer)?;
		let mut slatepack = Slatepack::default();
		slatepack.payload = byte_ser::to_bytes(&bin_slate).map_err(|_| ErrorKind::SlatepackSer)?;
		slatepack.sender = self.0.sender.clone();
		slatepack.try_encrypt_payload(self.0.recipients.clone())?;
		Ok(slatepack)
	}

	/// Armor a slatepack
	pub fn armor_slatepack(&self, slatepack: &Slatepack) -> Result<String, Error> {
		SlatepackArmor::encode(&slatepack)
	}

	/// Return/upgrade slate from slatepack
	pub fn get_slate(&self, slatepack: &Slatepack) -> Result<Slate, Error> {
		let slate_bin =
			byte_ser::from_bytes::<VersionedBinSlate>(&slatepack.payload).map_err(|e| {
				error!("Error reading slate from armored slatepack: {}", e);
				let msg = format!("{}", e);
				ErrorKind::SlatepackDeser(msg)
			})?;
		Ok(Slate::upgrade(slate_bin.into())?)
	}
}
