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

use bech32::{self, ToBase32};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
/// Slatepack Types + Serialization implementation
use ed25519_dalek::SecretKey as edSecretKey;
use sha2::{Digest, Sha512};
use x25519_dalek::StaticSecret;

use crate::dalek_ser;
use crate::grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use crate::{Error, ErrorKind};
use grin_wallet_util::byte_ser;

use super::SlatepackAddress;

use std::fmt;
use std::io::{Cursor, Read, Write};

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

	// Encrypted metadata, to be serialized into payload only
	// shouldn't be accessed directly
	/// Encrypted metadata
	#[serde(default = "default_enc_metadata")]
	#[serde(skip_serializing_if = "enc_metadata_is_empty")]
	encrypted_meta: SlatepackEncMetadata,

	// Payload (e.g. slate), including encrypted metadata, if present
	/// Binary payload, can be encrypted or plaintext
	#[serde(
		serialize_with = "dalek_ser::as_base64",
		deserialize_with = "dalek_ser::bytes_from_base64"
	)]
	pub payload: Vec<u8>,

	/// Test mode
	#[serde(default = "default_future_test_mode")]
	#[serde(skip)]
	pub future_test_mode: bool,
}

fn default_sender_none() -> Option<SlatepackAddress> {
	None
}

fn default_enc_metadata() -> SlatepackEncMetadata {
	SlatepackEncMetadata {
		sender: None,
		recipients: vec![],
	}
}

fn default_future_test_mode() -> bool {
	false
}

fn enc_metadata_is_empty(data: &SlatepackEncMetadata) -> bool {
	data.sender.is_none() && data.recipients.is_empty()
}

impl fmt::Display for Slatepack {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", serde_json::to_string_pretty(&self).unwrap())
	}
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
			encrypted_meta: default_enc_metadata(),
			payload: vec![],
			future_test_mode: false,
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

	// test function that pads the encrypted meta payload with unknown data
	fn pad_test_data(data: &mut Vec<u8>) {
		let extra_bytes = 139;
		let mut len_bytes = [0u8; 4];
		len_bytes.copy_from_slice(&data[0..4]);
		let mut meta_len = Cursor::new(len_bytes).read_u32::<BigEndian>().unwrap();
		meta_len += extra_bytes;
		let mut len_bytes = vec![];
		len_bytes.write_u32::<BigEndian>(meta_len).unwrap();
		data[..4].clone_from_slice(&len_bytes[..4]);
		for _ in 0..extra_bytes {
			data.push(rand::random())
		}
	}

	/// age encrypt the payload with the given public key
	pub fn try_encrypt_payload(&mut self, recipients: Vec<SlatepackAddress>) -> Result<(), Error> {
		if recipients.is_empty() {
			return Ok(());
		}

		// Move our sender to the encrypted metadata field
		self.encrypted_meta.sender = self.sender.clone();
		self.sender = None;

		// Create encrypted metadata, which will be length prefixed
		let bin_meta = SlatepackEncMetadataBin(self.encrypted_meta.clone());
		let mut to_encrypt = byte_ser::to_bytes(&bin_meta).map_err(|_| ErrorKind::SlatepackSer)?;

		if self.future_test_mode {
			Slatepack::pad_test_data(&mut to_encrypt);
		}

		to_encrypt.append(&mut self.payload);

		let rec_keys: Result<Vec<_>, _> = recipients
			.into_iter()
			.map(|addr| {
				let recp_key: age::x25519::Recipient = addr.to_age_pubkey_str()?.parse()?;
				Ok(Box::new(recp_key) as Box<dyn age::Recipient>)
			})
			.collect();

		let keys = match rec_keys {
			Ok(k) => k,
			Err(e) => return Err(e),
		};

		let encryptor = age::Encryptor::with_recipients(keys);
		let mut encrypted = vec![];
		let mut writer = encryptor.wrap_output(&mut encrypted)?;
		writer.write_all(&to_encrypt)?;
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
		let x_dec_secret_bech32 =
			bech32::encode("age-secret-key-", (&x_dec_secret).to_bytes().to_base32())?;
		let key: age::x25519::Identity = x_dec_secret_bech32.parse()?;

		let decryptor = match age::Decryptor::new(&self.payload[..])? {
			age::Decryptor::Recipients(d) => d,
			_ => unreachable!(),
		};
		let mut decrypted = vec![];
		let mut reader = decryptor.decrypt(std::iter::once(&key as &dyn age::Identity))?;
		reader.read_to_end(&mut decrypted)?;
		// Parse encrypted metadata from payload, first 4 bytes of decrypted payload
		// will be encrypted metadata length
		let mut len_bytes = [0u8; 4];
		len_bytes.copy_from_slice(&decrypted[0..4]);
		let meta_len = Cursor::new(len_bytes).read_u32::<BigEndian>()?;
		self.payload = decrypted.split_off(meta_len as usize + 4);
		let meta = byte_ser::from_bytes::<SlatepackEncMetadataBin>(&decrypted)
			.map_err(|_| ErrorKind::SlatepackSer)?
			.0;
		self.sender = meta.sender;
		self.encrypted_meta.recipients = meta.recipients;
		self.mode = 0;

		Ok(())
	}

	/// add a recipient to encrypted metadata
	pub fn add_recipient(&mut self, address: SlatepackAddress) {
		self.encrypted_meta.recipients.push(address)
	}

	/// retrieve recipients
	pub fn recipients(&self) -> &[SlatepackAddress] {
		&self.encrypted_meta.recipients
	}

	/// version check warning
	// TODO: API?
	pub fn ver_check_warn(&self) {
		if self.slatepack.major > SLATEPACK_MAJOR_VERSION
			|| (self.slatepack.major == SLATEPACK_MAJOR_VERSION
				&& self.slatepack.minor > SLATEPACK_MINOR_VERSION)
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

		// encrypted metadata is only included in the payload
		// on encryption, and is not serialised here

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
			encrypted_meta: default_enc_metadata(),
			payload,
			future_test_mode: false,
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

/// Encapsulates encrypted metadata fields
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SlatepackEncMetadata {
	/// Encrypted Sender address, if desired
	#[serde(default = "default_sender_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	sender: Option<SlatepackAddress>,
	/// Recipients list, if desired (mostly for future multiparty needs)
	#[serde(default = "default_recipients_empty")]
	#[serde(skip_serializing_if = "recipients_empty")]
	recipients: Vec<SlatepackAddress>,
}

fn recipients_empty(value: &[SlatepackAddress]) -> bool {
	value.is_empty()
}

fn default_recipients_empty() -> Vec<SlatepackAddress> {
	vec![]
}

impl SlatepackEncMetadata {
	// return length in bytes for encoding (without the 4 byte length header)
	pub fn encoded_len(&self) -> Result<usize, Error> {
		let mut length = 2; //opt flags
		if let Some(s) = &self.sender {
			length += s.encoded_len()?;
		}
		if !self.recipients.is_empty() {
			length += 2;
			for r in self.recipients.iter() {
				length += r.encoded_len()?;
			}
		}
		Ok(length)
	}
}

/// Wrapper for outputting encrypted metadata as binary
#[derive(Debug, Clone)]
pub struct SlatepackEncMetadataBin(pub SlatepackEncMetadata);

impl serde::Serialize for SlatepackEncMetadataBin {
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

impl<'de> serde::Deserialize<'de> for SlatepackEncMetadataBin {
	fn deserialize<D>(deserializer: D) -> Result<SlatepackEncMetadataBin, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		struct SlatepackEncMetadataBinVisitor;

		impl<'de> serde::de::Visitor<'de> for SlatepackEncMetadataBinVisitor {
			type Value = SlatepackEncMetadataBin;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(formatter, "a serialised binary Slatepack Metadata")
			}

			fn visit_bytes<E>(self, value: &[u8]) -> Result<SlatepackEncMetadataBin, E>
			where
				E: serde::de::Error,
			{
				let mut reader = std::io::Cursor::new(value.to_vec());
				let s = ser::deserialize(&mut reader, ser::ProtocolVersion(4))
					.map_err(|err| serde::de::Error::custom(err.to_string()))?;
				Ok(s)
			}
		}

		deserializer.deserialize_bytes(SlatepackEncMetadataBinVisitor)
	}
}

impl Writeable for SlatepackEncMetadataBin {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let inner = &self.0;
		// write entire metadata length
		writer.write_u32(inner.encoded_len().map_err(|e| {
			error!("Cannot write encrypted metadata length: {}", e);
			ser::Error::CorruptedData
		})? as u32)?;

		// 16 bits of optional content flags (2), most reserved for future use
		let mut opt_flags: u16 = 0;
		if inner.sender.is_some() {
			opt_flags |= 0x01;
		}
		if !inner.recipients.is_empty() {
			opt_flags |= 0x02;
		}
		writer.write_u16(opt_flags)?;

		if let Some(s) = &inner.sender {
			s.write(writer)?;
		};

		// Recipients List
		if !inner.recipients.is_empty() {
			let len = inner.recipients.len();
			// write number of recipients
			if len as u16 > std::u16::MAX {
				error!("Too many recipients: {}", len);
				return Err(ser::Error::CorruptedData);
			}
			writer.write_u16(len as u16)?;
			for r in inner.recipients.iter() {
				r.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for SlatepackEncMetadataBin {
	fn read<R: Reader>(reader: &mut R) -> Result<SlatepackEncMetadataBin, ser::Error> {
		// length header, always present
		let mut bytes_remaining = reader.read_u32()?;

		// optional content flags (2)
		let opt_flags = reader.read_u16()?;
		bytes_remaining -= 2;

		let sender = if opt_flags & 0x01 > 0 {
			let addr = SlatepackAddress::read(reader)?;
			let len = match addr.encoded_len() {
				Ok(e) => e as u32,
				Err(e) => {
					error!("Cannot parse Slatepack address: {}", e);
					return Err(ser::Error::CorruptedData);
				}
			};
			bytes_remaining -= len;
			Some(addr)
		} else {
			None
		};

		let mut recipients = vec![];
		if opt_flags & 0x02 > 0 {
			// number of recipients
			let count = reader.read_u16()?;
			bytes_remaining -= 2;
			for _ in 0..count {
				let addr = SlatepackAddress::read(reader)?;
				let len = match addr.encoded_len() {
					Ok(e) => e as u32,
					Err(e) => {
						error!("Cannot parse Slatepack address: {}", e);
						return Err(ser::Error::CorruptedData);
					}
				};
				bytes_remaining -= len;
				recipients.push(addr);
			}
		}

		// bleed off any unknown data beyond this
		while bytes_remaining > 0 {
			let _ = reader.read_u8()?;
			bytes_remaining -= 1;
		}

		Ok(SlatepackEncMetadataBin(SlatepackEncMetadata {
			sender,
			recipients,
		}))
	}
}

#[test]
fn slatepack_bin_basic_ser() -> Result<(), grin_wallet_util::byte_ser::Error> {
	use grin_wallet_util::byte_ser;
	let mut payload: Vec<u8> = Vec::with_capacity(243);
	for _ in 0..payload.capacity() {
		payload.push(rand::random());
	}
	let sp = Slatepack {
		payload,
		..Slatepack::default()
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
	use crate::grin_core::global;
	use grin_wallet_util::byte_ser;
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let mut payload: Vec<u8> = Vec::with_capacity(243);
	for _ in 0..payload.capacity() {
		payload.push(rand::random());
	}

	// includes optional fields
	let sender = Some(SlatepackAddress::random());
	let sp = Slatepack {
		sender,
		payload,
		..Slatepack::default()
	};
	let ser = byte_ser::to_bytes(&SlatepackBin(sp.clone()))?;
	let deser = byte_ser::from_bytes::<SlatepackBin>(&ser)?.0;
	assert_eq!(sp, deser);

	Ok(())
}

// ensure that a slatepack with unknown data in the optional fields can be read
#[test]
fn slatepack_bin_future() -> Result<(), grin_wallet_util::byte_ser::Error> {
	use crate::grin_core::global;
	use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
	use grin_wallet_util::byte_ser;
	use rand::{thread_rng, Rng};
	use std::io::Cursor;
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
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
		sender,
		payload: payload.clone(),
		..Slatepack::default()
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

	// sender 64

	let mut opt_fields_len_bytes = [0u8; 4];
	opt_fields_len_bytes.copy_from_slice(&ser[5..9]);
	let mut rdr = Cursor::new(opt_fields_len_bytes.to_vec());
	let opt_fields_len = rdr.read_u32::<BigEndian>().unwrap();
	// check this matches what we expect below
	assert_eq!(opt_fields_len, 65);

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

// test encryption and encrypted metadata, which only gets written
// if mode == 1
#[test]
fn slatepack_encrypted_meta() -> Result<(), Error> {
	use crate::grin_core::global;
	use crate::{Slate, SlateVersion, VersionedBinSlate, VersionedSlate};
	use ed25519_dalek::PublicKey as edDalekPublicKey;
	use ed25519_dalek::SecretKey as edDalekSecretKey;
	use rand::{thread_rng, Rng};
	use std::convert::TryFrom;
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

	let sec_key_bytes: [u8; 32] = thread_rng().gen();

	let ed_sec_key = edDalekSecretKey::from_bytes(&sec_key_bytes).unwrap();
	let ed_pub_key = edDalekPublicKey::from(&ed_sec_key);
	let addr = SlatepackAddress::new(&ed_pub_key);

	let encoded = String::try_from(&addr).unwrap();
	let parsed_addr = SlatepackAddress::try_from(encoded.as_str()).unwrap();
	assert_eq!(addr, parsed_addr);

	let mut slatepack = super::Slatepack::default();
	slatepack.sender = Some(SlatepackAddress::random());
	slatepack.add_recipient(SlatepackAddress::random());
	slatepack.add_recipient(SlatepackAddress::random());

	let v_slate = VersionedSlate::into_version(Slate::blank(2, false), SlateVersion::V4)?;
	let bin_slate = VersionedBinSlate::try_from(v_slate).map_err(|_| ErrorKind::SlatepackSer)?;
	slatepack.payload = byte_ser::to_bytes(&bin_slate).map_err(|_| ErrorKind::SlatepackSer)?;

	let orig_sp = slatepack.clone();

	slatepack.try_encrypt_payload(vec![addr.clone()])?;

	// sender should have been moved to encrypted meta
	assert!(slatepack.sender.is_none());

	let ser = byte_ser::to_bytes(&SlatepackBin(slatepack)).unwrap();
	let mut slatepack = byte_ser::from_bytes::<SlatepackBin>(&ser).unwrap().0;

	slatepack.try_decrypt_payload(Some(&ed_sec_key))?;
	assert!(slatepack.sender.is_some());

	assert_eq!(orig_sp, slatepack);

	Ok(())
}

// Ensure adding unknown (future) bytes to the encrypted
// metadata won't break parsing
#[test]
fn slatepack_encrypted_meta_future() -> Result<(), Error> {
	use crate::grin_core::global;
	use crate::{Slate, SlateVersion, VersionedBinSlate, VersionedSlate};
	use ed25519_dalek::PublicKey as edDalekPublicKey;
	use ed25519_dalek::SecretKey as edDalekSecretKey;
	use rand::{thread_rng, Rng};
	use std::convert::TryFrom;
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

	let sec_key_bytes: [u8; 32] = thread_rng().gen();

	let ed_sec_key = edDalekSecretKey::from_bytes(&sec_key_bytes).unwrap();
	let ed_pub_key = edDalekPublicKey::from(&ed_sec_key);
	let addr = SlatepackAddress::new(&ed_pub_key);

	let encoded = String::try_from(&addr).unwrap();
	let parsed_addr = SlatepackAddress::try_from(encoded.as_str()).unwrap();
	assert_eq!(addr, parsed_addr);

	let mut slatepack = Slatepack::default();
	slatepack.sender = Some(SlatepackAddress::random());
	slatepack.add_recipient(SlatepackAddress::random());
	slatepack.add_recipient(SlatepackAddress::random());

	let v_slate = VersionedSlate::into_version(Slate::blank(2, false), SlateVersion::V4)?;
	let bin_slate = VersionedBinSlate::try_from(v_slate).map_err(|_| ErrorKind::SlatepackSer)?;
	slatepack.payload = byte_ser::to_bytes(&bin_slate).map_err(|_| ErrorKind::SlatepackSer)?;

	let orig_sp = slatepack.clone();

	slatepack.future_test_mode = true;

	slatepack.try_encrypt_payload(vec![addr.clone()])?;

	// sender should have been moved to encrypted meta
	assert!(slatepack.sender.is_none());

	let ser = byte_ser::to_bytes(&SlatepackBin(slatepack)).unwrap();
	let mut slatepack = byte_ser::from_bytes::<SlatepackBin>(&ser).unwrap().0;

	slatepack.try_decrypt_payload(Some(&ed_sec_key))?;
	assert!(slatepack.sender.is_some());

	assert_eq!(orig_sp, slatepack);

	Ok(())
}
