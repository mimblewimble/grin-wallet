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

/// Slatepack Types + Serialization implementation
use ed25519_dalek::PublicKey as DalekPublicKey;

use crate::dalek_ser;
use crate::grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use crate::util::byte_ser;

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
	#[serde(default = "default_sender_none")]
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

fn default_sender_none() -> Option<DalekPublicKey> {
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

impl Slatepack {
	/// return length of optional fields
	pub fn opt_fields_len(&self) -> Result<usize, ser::Error> {
		let mut retval = 0;
		if self.sender.is_some() {
			retval += 4;
		}
		Ok(retval)
	}
	/// return the length of the header
	pub fn header_len(&self) -> Result<usize, ser::Error> {
		match self.header.as_ref() {
			None => Ok(0),
			Some(h) => h.len(),
		}
	}
}

/// Wrapper for outputting slate as binary
#[derive(Debug, Clone)]
pub struct SlatepackBin(pub Slatepack);

impl serde::Serialize for SlatepackBin {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let mut vec = vec![];
		ser::serialize(&mut vec, ser::ProtocolVersion(4), self)
			.map_err(|err| serde::ser::Error::custom(err.to_string()))?;
		serializer.serialize_bytes(&vec)
	}
}

impl<'de> serde::Deserialize<'de> for SlatepackBin {
	fn deserialize<D>(deserializer: D) -> Result<SlatepackBin, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		struct SlatepackBinVisitor;

		impl<'de> serde::de::Visitor<'de> for SlatepackBinVisitor {
			type Value = SlatepackBin;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(formatter, "a serialised binary Slatepack")
			}

			fn visit_bytes<E>(self, value: &[u8]) -> Result<SlatepackBin, E>
			where
				E: serde::de::Error,
			{
				let mut reader = std::io::Cursor::new(value.to_vec());
				let s = ser::deserialize(&mut reader, ser::ProtocolVersion(4))
					.map_err(|err| serde::de::Error::custom(err.to_string()))?;
				Ok(s)
			}
		}

		deserializer.deserialize_bytes(SlatepackBinVisitor)
	}
}

impl Writeable for SlatepackBin {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let sp = self.0.clone();
		// Version (2)
		sp.slatepack.write(writer)?;
		// Mode (1)
		writer.write_u8(sp.mode)?;
		// 16 bits of optional content flags (2), most reserved for future use
		let mut opt_flags: u16 = 0;
		if sp.sender.is_some() {
			opt_flags |= 0x01;
		}
		writer.write_u16(opt_flags)?;

		// Bytes to skip from here (Start of optional fields other than header) to get to header (4)
		writer.write_u32(sp.opt_fields_len()? as u32)?;

		// write optional fields
		if let Some(s) = sp.sender {
			writer.write_fixed_bytes(s.to_bytes())?;
		};

		// Write Length of header
		writer.write_u32(sp.header_len()? as u32)?;

		// write header
		if let Some(h) = &sp.header {
			h.write(writer)?;
		}

		// Now write payload (length prefixed)
		writer.write_bytes(sp.payload.clone())
	}
}

impl Readable for SlatepackBin {
	fn read<R: Reader>(reader: &mut R) -> Result<SlatepackBin, ser::Error> {
		// Version (2)
		let slatepack = SlatepackVersion::read(reader)?;
		// Mode (1)
		let mode = reader.read_u8()?;
		if mode > 1 {
			return Err(ser::Error::UnexpectedData {
				expected: vec![0, 1],
				received: vec![mode],
			});
		}
		// optional content flags (2)
		let opt_flags = reader.read_u16()?;
		// start of header
		let mut bytes_to_header = reader.read_u32()?;

		let sender = if opt_flags & 0x01 > 0 {
			bytes_to_header -= 32;
			Some(DalekPublicKey::from_bytes(&reader.read_fixed_bytes(32)?).unwrap())
		} else {
			None
		};

		// skip over any unknown future fields until header
		while bytes_to_header > 0 {
			let _ = reader.read_u8()?;
			bytes_to_header -= 1;
		}

		// read length of header
		let header_len = reader.read_u32()?;

		let header = if header_len > 0 {
			Some(SlatepackHeader::read(reader)?)
		} else {
			None
		};

		let payload = reader.read_bytes_len_prefix()?;

		Ok(SlatepackBin(Slatepack {
			slatepack,
			mode,
			sender,
			header,
			payload,
		}))
	}
}

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

impl SlatepackHeader {
	/// return length
	pub fn len(&self) -> Result<usize, ser::Error> {
		Ok(byte_ser::to_bytes(self)
			.map_err(|_| ser::Error::CorruptedData)?
			.len())
	}
}

impl Writeable for &SlatepackHeader {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// write number of entries
		writer.write_u8(self.recipients_list.len() as u8)?;
		for r in self.recipients_list.iter() {
			r.write(writer)?;
		}
		// Mac
		writer.write_fixed_bytes(&self.mac)
	}
}

impl Readable for SlatepackHeader {
	fn read<R: Reader>(reader: &mut R) -> Result<SlatepackHeader, ser::Error> {
		let num_entries = reader.read_u8()?;
		let mut ret_val = SlatepackHeader {
			recipients_list: vec![],
			mac: [0; 32],
		};
		for _ in 0..num_entries {
			ret_val
				.recipients_list
				.push(RecipientListEntry::read(reader)?);
		}
		let mac_bytes = reader.read_fixed_bytes(32)?;
		ret_val.mac.copy_from_slice(&mac_bytes[0..32]);
		Ok(ret_val)
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
