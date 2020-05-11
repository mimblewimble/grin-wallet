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

use ed25519_dalek::PublicKey as DalekPublicKey;

use crate::client_utils::byte_ser;
use crate::core::ser::{self, Readable, Reader, Writeable, Writer};
use crate::libwallet::{
	dalek_ser, Error, ErrorKind, Slate, SlateVersion, VersionedBinSlate, VersionedSlate,
};
use crate::{SlateGetter, SlatePutter};

/// Basic Slatepack definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Slatepack {
	// Required Fields
	/// Versioning info
	#[serde(with = "slatepack_version")]
	pub slatepack: SlatepackVersion,
	/// Delivery Mode, 0 = plain_text, 1 = encrypted
	pub mode: u8,
	/// Sender address
	#[serde(with = "dalek_ser::option_dalek_pubkey_base64")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sender: Option<DalekPublicKey>,
	/// Header, used if encryption enabled, mode == 1
	#[serde(default = "default_header_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub header: Option<SlatepackHeader>,
	/// Binary payload, can be encrypted or plaintext
	#[serde(
		serialize_with = "dalek_ser::as_base64",
		deserialize_with = "dalek_ser::bytes_from_base64"
	)]
	pub payload: Vec<u8>,
}

fn default_header_none() -> Option<SlatepackHeader> {
	None
}

impl Default for Slatepack {
	fn default() -> Self {
		Self {
			slatepack: SlatepackVersion { major: 0, minor: 1 },
			mode: 0,
			sender: None,
			header: None,
			payload: vec![],
		}
	}
}

impl Writeable for &Slatepack {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.slatepack.write(writer)?;
		writer.write_u8(self.mode)?;
		// Write 1 or 0 depending on whether sender is present. Can add
		// more fields in later versions
		match self.sender {
			None => writer.write_u8(0)?,
			Some(p) => {
				writer.write_u8(1)?;
				writer.write_fixed_bytes(p.to_bytes())?;
			}
		};
		(SlatepackHeaderWrapRef(&self.header)).write(writer)?;
		writer.write_bytes(self.payload.clone())?;
		Ok(())
	}
}

/*impl Readable for Slatepack {
	fn read<R: Reader>(reader: &mut R) -> Result<Slatepack, ser::Error> {
		let slatepack = SlatepackVersion::read(reader)?;
		let mode = reader.read_u8()?;
		if mode > 1 {
			return Err(serde::de::Error::custom("Unknown Mode"))?;
		}
		let sender_present = reader.read_u8()?;

		let sender = match sender_present {
			0 => {
				None
			},
			1 => {
				let s = DalekPublicKey::from_bytes(&reader.read_fixed_bytes(32)?).unwrap();
				Some(s)
			},
			n => return Err(serde::de::Error::custom("Unknown Sender Flag"))?;
		};
	}
}*/

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SlatepackVersion {
	/// Major
	pub major: u8,
	/// Minor
	pub minor: u8,
}

impl Writeable for SlatepackVersion {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.major)?;
		writer.write_u8(self.minor)
	}
}

impl Readable for SlatepackVersion {
	fn read<R: Reader>(reader: &mut R) -> Result<SlatepackVersion, ser::Error> {
		let major = reader.read_u8()?;
		let minor = reader.read_u8()?;
		Ok(SlatepackVersion { major, minor })
	}
}

/// Serializes version field JSON
pub mod slatepack_version {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};

	use super::SlatepackVersion;

	///
	pub fn serialize<S>(v: &SlatepackVersion, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&format!("{}.{}", v.major, v.minor))
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<SlatepackVersion, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer).and_then(|s| {
			let mut retval = SlatepackVersion { major: 0, minor: 0 };
			let v: Vec<&str> = s.split('.').collect();
			if v.len() != 2 {
				return Err(Error::custom("Cannot parse version"));
			}
			match u8::from_str_radix(v[0], 10) {
				Ok(u) => retval.major = u,
				Err(e) => return Err(Error::custom(format!("Cannot parse version: {}", e))),
			}
			match u8::from_str_radix(v[1], 10) {
				Ok(u) => retval.minor = u,
				Err(e) => return Err(Error::custom(format!("Cannot parse version: {}", e))),
			}
			Ok(retval)
		})
	}
}

/// Header struct definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlatepackHeader {
	/// List of recipients, entry for each
	recipients_list: Vec<RecipientListEntry>,
	/// MAC on all "header" data up to the MAC
	//TODO: check length
	mac: [u8; 32],
}

struct SlatepackHeaderWrapRef<'a>(&'a Option<SlatepackHeader>);

impl<'a> Writeable for SlatepackHeaderWrapRef<'a> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if let Some(h) = self.0 {
			// write number of entries
			writer.write_u8(h.recipients_list.len() as u8)?;
			for r in h.recipients_list.iter() {
				r.write(writer)?;
			}
			// Mac
			writer.write_fixed_bytes(&h.mac)?;
		}
		Ok(())
	}
}

/// Header struct definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecipientListEntry {
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	/// Ephemeral public key
	epk: DalekPublicKey,
	/// Ephemeral message key, equivalent to file_key in age
	/// TODO: Check length
	emk: [u8; 32],
}

impl Writeable for RecipientListEntry {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.epk.to_bytes())?;
		writer.write_fixed_bytes(&self.emk)
	}
}

impl Readable for RecipientListEntry {
	fn read<R: Reader>(reader: &mut R) -> Result<RecipientListEntry, ser::Error> {
		let epk = DalekPublicKey::from_bytes(&reader.read_fixed_bytes(32)?).unwrap();
		let emk_bytes = reader.read_fixed_bytes(32)?;
		let mut emk = [0u8; 32];
		emk.copy_from_slice(&emk_bytes[0..32]);
		Ok(RecipientListEntry { epk, emk })
	}
}

#[derive(Clone)]
pub struct PathToSlatePack(pub PathBuf);

impl SlatePutter for PathToSlatePack {
	fn put_tx(&self, slate: &Slate, _as_bin: bool) -> Result<(), Error> {
		let mut pub_tx = File::create(&self.0)?;
		let out_slate = VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?;
		let bin_slate = VersionedBinSlate::try_from(out_slate).map_err(|_| ErrorKind::SlateSer)?;
		let mut slatepack = Slatepack::default();
		slatepack.payload = byte_ser::to_bytes(&bin_slate).map_err(|_| ErrorKind::SlateSer)?;
		/*if as_bin {
			let bin_slate =
				VersionedBinSlate::try_from(out_slate).map_err(|_| ErrorKind::SlateSer)?;
			pub_tx.write_all(&byte_ser::to_bytes(&bin_slate).map_err(|_| ErrorKind::SlateSer)?)?;
		} else {*/
		pub_tx.write_all(
			serde_json::to_string_pretty(&slatepack)
				.map_err(|_| ErrorKind::SlateSer)?
				.as_bytes(),
		)?;
		/*}*/
		pub_tx.sync_all()?;
		Ok(())
	}
}

impl SlateGetter for PathToSlatePack {
	fn get_tx(&self) -> Result<(Slate, bool), Error> {
		// try as bin first, then as json
		let mut pub_tx_f = File::open(&self.0)?;
		let mut data = Vec::new();
		pub_tx_f.read_to_end(&mut data)?;
		let bin_res = byte_ser::from_bytes::<VersionedBinSlate>(&data);
		if let Err(e) = bin_res {
			debug!("Not a valid binary slate: {} - Will try JSON", e);
		} else {
			if let Ok(s) = bin_res {
				return Ok((Slate::upgrade(s.into())?, true));
			}
		}

		// Otherwise try json
		let content = String::from_utf8(data).map_err(|_| ErrorKind::SlateSer)?;
		Ok((Slate::deserialize_upgrade(&content)?, false))
	}
}
