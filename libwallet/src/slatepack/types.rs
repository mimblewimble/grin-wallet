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
use ed25519_dalek::SecretKey as edSecretKey;
use sha2::{Digest, Sha512};
use x25519_dalek::StaticSecret;

use crate::dalek_ser;
use crate::grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use crate::Error;

use super::SlatepackAddress;

use std::convert::TryInto;
use std::io::{Read, Write};

pub const SLATEPACK_MAJOR_VERSION: u8 = 1;
pub const SLATEPACK_MINOR_VERSION: u8 = 0;

/// Basic Slatepack definition
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Slatepack {
	// Required Fields
	/// Versioning info
	#[serde(with = "slatepack_version")]
	pub slatepack: SlatepackVersion,
	/// Delivery Mode, 0 = plain_text, 1 = age encrypted
	pub mode: u8,

	// Optional Fields
	/// Optional Sender address
	#[serde(default = "default_sender_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sender: Option<SlatepackAddress>,

	// Payload
	/// Binary payload, can be encrypted or plaintext
	#[serde(
		serialize_with = "dalek_ser::as_base64",
		deserialize_with = "dalek_ser::bytes_from_base64"
	)]
	pub payload: Vec<u8>,
}

fn default_sender_none() -> Option<SlatepackAddress> {
	None
}

impl Default for Slatepack {
	fn default() -> Self {
		Self {
			slatepack: SlatepackVersion {
				major: SLATEPACK_MAJOR_VERSION,
				minor: SLATEPACK_MINOR_VERSION,
			},
			mode: 0,
			sender: None,
			payload: vec![],
		}
	}
}

impl Slatepack {
	/// return length of optional fields
	pub fn opt_fields_len(&self) -> Result<usize, ser::Error> {
		let mut retval = 0;
		if let Some(s) = self.sender.as_ref() {
			retval += s.encoded_len().unwrap();
		}
		Ok(retval)
	}

	/// age encrypt the payload with the given public key
	pub fn try_encrypt_payload(&mut self, recipients: Vec<SlatepackAddress>) -> Result<(), Error> {
		if recipients.is_empty() {
			return Ok(());
		}
		let rec_keys: Result<Vec<_>, _> = recipients
			.into_iter()
			.map(|addr| {
				let key = age::keys::RecipientKey::X25519((&addr).try_into()?);
				Ok(key)
			})
			.collect();

		let keys = match rec_keys {
			Ok(k) => k,
			Err(e) => return Err(e),
		};

		let encryptor = age::Encryptor::with_recipients(keys);
		let mut encrypted = vec![];
		let mut writer = encryptor.wrap_output(&mut encrypted, age::Format::Binary)?;
		writer.write_all(&self.payload)?;
		writer.finish()?;
		self.payload = encrypted.to_vec();
		self.mode = 1;
		Ok(())
	}

	/// As above, decrypt if needed
	pub fn try_decrypt_payload(&mut self, dec_key: Option<&edSecretKey>) -> Result<(), Error> {
		if self.mode == 0 {
			return Ok(());
		}
		let dec_key = match dec_key {
			Some(k) => k,
			None => return Ok(()),
		};
		let mut b = [0u8; 32];
		b.copy_from_slice(&dec_key.as_bytes()[0..32]);
		let mut hasher = Sha512::new();
		hasher.input(b);
		let result = hasher.result();
		b.copy_from_slice(&result[0..32]);

		let x_dec_secret = StaticSecret::from(b);
		let key = age::keys::SecretKey::X25519(x_dec_secret);

		let decryptor = match age::Decryptor::new(&self.payload[..])? {
			age::Decryptor::Recipients(d) => d,
			_ => unreachable!(),
		};
		let mut decrypted = vec![];
		let mut reader = decryptor.decrypt(&[key.into()])?;
		reader.read_to_end(&mut decrypted)?;
		self.payload = decrypted.to_vec();
		Ok(())
	}

	/// version check warning
	// TODO: API?
	pub fn ver_check_warn(&self) {
		if self.slatepack.major > SLATEPACK_MAJOR_VERSION
			|| (self.slatepack.major == SLATEPACK_MAJOR_VERSION
				&& self.slatepack.minor < SLATEPACK_MINOR_VERSION)
		{
			warn!("Incoming Slatepack's version is greater than what this wallet recognizes");
			warn!("You may need to upgrade if it contains unsupported features");
			warn!(
				"Incoming: {}.{}, This wallet: {}.{}",
				self.slatepack.major,
				self.slatepack.minor,
				SLATEPACK_MAJOR_VERSION,
				SLATEPACK_MINOR_VERSION
			);
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

		// Bytes to skip from here (Start of optional fields) to get to payload
		writer.write_u32(sp.opt_fields_len()? as u32)?;

		// write optional fields
		if let Some(s) = sp.sender {
			s.write(writer)?;
		};

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
		let mut bytes_to_payload = reader.read_u32()?;

		let sender = if opt_flags & 0x01 > 0 {
			let addr = SlatepackAddress::read(reader)?;
			let len = match addr.encoded_len() {
				Ok(e) => e as u32,
				Err(e) => {
					error!("Cannot parse Slatepack address: {}", e);
					return Err(ser::Error::CorruptedData);
				}
			};
			bytes_to_payload -= len;
			Some(addr)
		} else {
			None
		};

		// skip over any unknown future fields until header
		while bytes_to_payload > 0 {
			let _ = reader.read_u8()?;
			bytes_to_payload -= 1;
		}

		let payload = reader.read_bytes_len_prefix()?;

		Ok(SlatepackBin(Slatepack {
			slatepack,
			mode,
			sender,
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

#[test]
fn slatepack_bin_basic_ser() -> Result<(), grin_wallet_util::byte_ser::Error> {
	use grin_wallet_util::byte_ser;
	let slatepack = SlatepackVersion { major: 1, minor: 0 };
	let mut payload: Vec<u8> = Vec::with_capacity(243);
	for _ in 0..payload.capacity() {
		payload.push(rand::random());
	}
	let sp = Slatepack {
		slatepack,
		mode: 1,
		sender: None,
		payload,
	};
	let ser = byte_ser::to_bytes(&SlatepackBin(sp.clone()))?;
	let deser = byte_ser::from_bytes::<SlatepackBin>(&ser)?.0;
	assert_eq!(sp.slatepack, deser.slatepack);
	assert_eq!(sp.mode, deser.mode);
	assert!(sp.sender.is_none());
	Ok(())
}

#[test]
fn slatepack_bin_opt_fields_ser() -> Result<(), grin_wallet_util::byte_ser::Error> {
	use grin_wallet_util::byte_ser;
	let slatepack = SlatepackVersion { major: 1, minor: 0 };
	let mut payload: Vec<u8> = Vec::with_capacity(243);
	for _ in 0..payload.capacity() {
		payload.push(rand::random());
	}

	// includes optional fields
	let sender = Some(SlatepackAddress::random());
	let sp = Slatepack {
		slatepack,
		mode: 1,
		sender,
		payload,
	};
	let ser = byte_ser::to_bytes(&SlatepackBin(sp.clone()))?;
	let deser = byte_ser::from_bytes::<SlatepackBin>(&ser)?.0;
	assert_eq!(sp, deser);

	Ok(())
}

// ensure that a slatepack with unknown data in the optional fields can be read
#[test]
fn slatepack_bin_future() -> Result<(), grin_wallet_util::byte_ser::Error> {
	use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
	use grin_wallet_util::byte_ser;
	use rand::{thread_rng, Rng};
	use std::io::Cursor;

	let slatepack = SlatepackVersion { major: 1, minor: 0 };
	let payload_size = 1234;
	let mut payload: Vec<u8> = Vec::with_capacity(payload_size);
	for _ in 0..payload.capacity() {
		payload.push(rand::random());
	}
	let sender = Some(SlatepackAddress::random());

	println!(
		"sender len: {}",
		sender.as_ref().unwrap().encoded_len().unwrap()
	);

	let sp = Slatepack {
		slatepack,
		mode: 1,
		sender,
		payload: payload.clone(),
	};
	let ser = byte_ser::to_bytes(&SlatepackBin(sp.clone()))?;

	// Add an amount of meaningless (to us) data
	let num_extra_bytes = 248;
	let mut new_bytes = vec![];
	// Version 2
	// mode 1
	// opt flags 2
	// opt fields len (bytes to payload) 4
	// bytes 5-8 are opt fields len

	// sender 68

	let mut opt_fields_len_bytes = [0u8; 4];
	opt_fields_len_bytes.copy_from_slice(&ser[5..9]);
	let mut rdr = Cursor::new(opt_fields_len_bytes.to_vec());
	let opt_fields_len = rdr.read_u32::<BigEndian>().unwrap();
	// check this matches what we expect below
	assert_eq!(opt_fields_len, 69);

	let end_head_pos = opt_fields_len as usize + 8 + 1;

	for i in 0..end_head_pos {
		new_bytes.push(ser[i]);
	}
	for _ in 0..num_extra_bytes {
		new_bytes.push(thread_rng().gen());
	}
	for i in 0..8 {
		//push payload length prefix
		new_bytes.push(ser[end_head_pos + i]);
	}
	for i in 0..payload_size {
		new_bytes.push(ser[end_head_pos + 8 + i]);
	}

	assert_eq!(new_bytes.len(), ser.len() + num_extra_bytes as usize);

	// and set new opt fields length
	let mut wtr = vec![];
	wtr.write_u32::<BigEndian>(opt_fields_len + num_extra_bytes as u32)
		.unwrap();
	for i in 0..wtr.len() {
		new_bytes[5 + i] = wtr[i];
	}

	let deser = byte_ser::from_bytes::<SlatepackBin>(&new_bytes)?.0;
	assert_eq!(sp, deser);
	Ok(())
}
