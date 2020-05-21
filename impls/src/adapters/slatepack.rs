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
/// Slatepack Output 'plugin' implementation
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use x25519_dalek::PublicKey as xDalekPublicKey;
use x25519_dalek::StaticSecret;

use crate::libwallet::{
	Error, ErrorKind, Slate, SlateVersion, Slatepack, SlatepackArmor, SlatepackBin,
	VersionedBinSlate, VersionedSlate,
};
use crate::{SlateGetter, SlatePutter};
use grin_wallet_util::byte_ser;

#[derive(Clone)]
pub struct SlatepackArgs<'a> {
	pub pathbuf: PathBuf,
	pub sender: Option<xDalekPublicKey>,
	pub recipients: Vec<xDalekPublicKey>,
	pub dec_key: Option<&'a StaticSecret>,
}

pub struct PathToSlatepack<'a>(SlatepackArgs<'a>);

impl<'a> PathToSlatepack<'a> {
	/// Create with pathbuf and recipients
	pub fn new(args: SlatepackArgs<'a>) -> Self {
		Self(args)
	}

	pub fn get_slatepack_file_contents(&self) -> Result<Vec<u8>, Error> {
		let mut pub_tx_f = File::open(&self.0.pathbuf)?;
		let mut data = Vec::new();
		pub_tx_f.read_to_end(&mut data)?;
		Ok(data)
	}

	// return slatepack itself
	pub fn deser_slatepack(&self, data: Vec<u8>) -> Result<Slatepack, Error> {
		// try as bin first, then as json
		let bin_res = byte_ser::from_bytes::<SlatepackBin>(&data);
		match bin_res {
			Err(e) => debug!("Not a valid binary slatepack: {} - Will try JSON", e),
			Ok(s) => return Ok(s.0),
		}
		// Otherwise try json
		let content = String::from_utf8(data).map_err(|_| ErrorKind::SlatepackDeser)?;
		let slatepack: Slatepack = serde_json::from_str(&content).map_err(|e| {
			error!("Error reading JSON Slatepack: {}", e);
			ErrorKind::SlatepackDeser
		})?;
		Ok(slatepack)
	}

	pub fn get_slatepack(&self) -> Result<Slatepack, Error> {
		let data = self.get_slatepack_file_contents()?;
		self.deser_slatepack(data)
	}

	// Create slatepack from slate and args
	pub fn create_slatepack(&self, slate: &Slate) -> Result<Slatepack, Error> {
		let out_slate = VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?;
		let bin_slate =
			VersionedBinSlate::try_from(out_slate).map_err(|_| ErrorKind::SlatepackSer)?;
		let mut slatepack = Slatepack::default();
		slatepack.payload = byte_ser::to_bytes(&bin_slate).map_err(|_| ErrorKind::SlatepackSer)?;
		slatepack.sender = self.0.sender;
		slatepack.try_encrypt_payload(self.0.recipients.clone())?;
		Ok(slatepack)
	}
}

impl<'a> SlatePutter for PathToSlatepack<'a> {
	fn put_tx(&self, slate: &Slate, as_bin: bool) -> Result<(), Error> {
		let slatepack = self.create_slatepack(slate)?;
		let mut pub_tx = File::create(&self.0.pathbuf)?;
		if as_bin {
			pub_tx.write_all(
				&byte_ser::to_bytes(&SlatepackBin(slatepack))
					.map_err(|_| ErrorKind::SlatepackSer)?,
			)?;
		} else {
			pub_tx.write_all(
				serde_json::to_string_pretty(&slatepack)
					.map_err(|_| ErrorKind::SlateSer)?
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
		let mut slatepack = self.deser_slatepack(data)?;
		slatepack.try_decrypt_payload(self.0.dec_key)?;
		let slate = byte_ser::from_bytes::<VersionedBinSlate>(&slatepack.payload)
			.map_err(|_| ErrorKind::SlatepackSer)?;
		Ok((Slate::upgrade(slate.into())?, true))
	}
}

pub struct PathToSlatepackArmored<'a>(SlatepackArgs<'a>);

impl<'a> PathToSlatepackArmored<'a> {
	/// Create with pathbuf and recipients
	pub fn new(args: SlatepackArgs<'a>) -> Self {
		Self(args)
	}

	/// decode armor
	pub fn decode_armored_file(&self) -> Result<Vec<u8>, Error> {
		let mut pub_sp_armored = File::open(&self.0.pathbuf)?;
		let mut data = Vec::new();
		pub_sp_armored.read_to_end(&mut data)?;
		SlatepackArmor::decode(&String::from_utf8(data).unwrap())
	}

	// return slatepack
	pub fn get_slatepack(&self) -> Result<Slatepack, Error> {
		let data = self.decode_armored_file()?;
		let pts = PathToSlatepack::new(self.0.clone());
		pts.deser_slatepack(data)
	}
}

impl<'a> SlatePutter for PathToSlatepackArmored<'a> {
	fn put_tx(&self, slate: &Slate, _as_bin: bool) -> Result<(), Error> {
		let pts = PathToSlatepack::new(self.0.clone());
		let slatepack = pts.create_slatepack(slate)?;
		let armored = SlatepackArmor::encode(&slatepack, 3)?;
		let mut pub_tx = File::create(&self.0.pathbuf)?;
		pub_tx.write_all(armored.as_bytes())?;
		pub_tx.sync_all()?;
		Ok(())
	}
}

impl<'a> SlateGetter for PathToSlatepackArmored<'a> {
	fn get_tx(&self) -> Result<(Slate, bool), Error> {
		let mut slatepack = self.get_slatepack()?;
		slatepack.try_decrypt_payload(self.0.dec_key)?;
		let slate_bin =
			byte_ser::from_bytes::<VersionedBinSlate>(&slatepack.payload).map_err(|e| {
				error!("Error reading slate from armored slatepack: {}", e);
				ErrorKind::SlatepackDeser
			})?;
		Ok((Slate::upgrade(slate_bin.into())?, true))
	}
}
