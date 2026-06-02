// Copyright 2023 The Grin Developers
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

//! Util fns for mwixnet
//! TODO: possibly redundant, check or move elsewhere

use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use std::convert::TryInto;

/// Writes an optional value as '1' + value if Some, or '0' if None
///
/// This function is used to serialize an optional value into a Writer. If the option
/// contains Some value, it writes '1' followed by the serialized value. If the option
/// is None, it just writes '0'.
///
/// # Arguments
///
/// * `writer` - A Writer instance where the data will be written.
/// * `o` - The Optional value that will be written.
///
/// # Returns
///
/// * If successful, returns Ok with nothing.
/// * If an error occurs during writing, returns Err wrapping the error.
///
/// # Example
///
/// ```
///	use grin_wallet_libwallet::mwixnet::onion_util::write_optional;
/// let mut writer:Vec<u8> = vec![];
/// let optional_value: Option<u32> = Some(10);
/// //write_optional(&mut writer, &optional_value);
/// ```
pub fn write_optional<O: Writeable, W: Writer>(
	writer: &mut W,
	o: &Option<O>,
) -> Result<(), ser::Error> {
	match &o {
		Some(o) => {
			writer.write_u8(1)?;
			o.write(writer)?;
		}
		None => writer.write_u8(0)?,
	};
	Ok(())
}

/// Reads an optional value as '1' + value if Some, or '0' if None
///
/// This function is used to deserialize an optional value from a Reader. If the first byte
/// read is '0', it returns None. If the first byte is '1', it reads the next value and
/// returns Some(value).
///
/// # Arguments
///
/// * `reader` - A Reader instance from where the data will be read.
///
/// # Returns
///
/// * If successful, returns Ok wrapping an optional value. If the first byte read was '0',
///   returns None. If it was '1', returns Some(value).
/// * If an error occurs during reading, returns Err wrapping the error.
///
/// # Example
///
/// ```
///	use grin_wallet_libwallet::mwixnet::onion_util::read_optional;
/// use grin_core::ser::{BinReader, ProtocolVersion, DeserializationMode};
/// let mut buf: &[u8] = &[1, 0, 0, 0, 10];
/// let mut reader = BinReader::new(&mut buf, ProtocolVersion::local(), DeserializationMode::default());
/// let optional_value: Option<u32> = read_optional(&mut reader).unwrap();
/// assert_eq!(optional_value, Some(10));
/// ```
pub fn read_optional<O: Readable, R: Reader>(reader: &mut R) -> Result<Option<O>, ser::Error> {
	let o = if reader.read_u8()? == 0 {
		None
	} else {
		Some(O::read(reader)?)
	};
	Ok(o)
}

/// Convert a vector to an array of size `S`.
///
/// # Arguments
///
/// * `vec` - The input vector.
///
/// # Returns
///
/// * If successful, returns an `Ok` wrapping an array of size `S` containing
/// the first `S` bytes of `vec`.
/// * If `vec` is smaller than `S`, returns an `Err` indicating a count error.
///
/// # Example
///
/// ```
///	use grin_wallet_libwallet::mwixnet::onion_util::vec_to_array;
/// let v = vec![0, 1, 2, 3, 4, 5];
/// let a = vec_to_array::<4>(&v).unwrap();
/// assert_eq!(a, [0, 1, 2, 3]);
/// ```
pub fn vec_to_array<const S: usize>(vec: &Vec<u8>) -> Result<[u8; S], ser::Error> {
	if vec.len() < S {
		return Err(ser::Error::CountError);
	}
	let arr: [u8; S] = vec[0..S].try_into().unwrap();
	Ok(arr)
}

#[cfg(test)]
mod tests {
	use super::*;
	use grin_core::ser::{BinReader, BinWriter, DeserializationMode, ProtocolVersion};

	#[test]
	fn test_write_optional() {
		// Test with Some value
		let mut buf: Vec<u8> = vec![];
		let val: Option<u32> = Some(10);
		write_optional(&mut BinWriter::default(&mut buf), &val).unwrap();
		assert_eq!(buf, &[1, 0, 0, 0, 10]); // 1 for Some, then 10 as a little-endian u32

		// Test with None value
		buf.clear();
		let val: Option<u32> = None;
		write_optional(&mut BinWriter::default(&mut buf), &val).unwrap();
		assert_eq!(buf, &[0]); // 0 for None
	}

	#[test]
	fn test_read_optional() {
		// Test with Some value
		let mut buf: &[u8] = &[1, 0, 0, 0, 10]; // 1 for Some, then 10 as a little-endian u32
		let val: Option<u32> = read_optional(&mut BinReader::new(
			&mut buf,
			ProtocolVersion::local(),
			DeserializationMode::default(),
		))
		.unwrap();
		assert_eq!(val, Some(10));

		// Test with None value
		buf = &[0]; // 0 for None
		let val: Option<u32> = read_optional(&mut BinReader::new(
			&mut buf,
			ProtocolVersion::local(),
			DeserializationMode::default(),
		))
		.unwrap();
		assert_eq!(val, None);
	}

	#[test]
	fn test_vec_to_array_success() {
		let v = vec![1, 2, 3, 4, 5, 6, 7, 8];
		let a = vec_to_array::<4>(&v).unwrap();
		assert_eq!(a, [1, 2, 3, 4]);
	}

	#[test]
	fn test_vec_to_array_too_small() {
		let v = vec![1, 2, 3];
		let res = vec_to_array::<4>(&v);
		assert!(res.is_err());
	}

	#[test]
	fn test_vec_to_array_empty() {
		let v = vec![];
		let res = vec_to_array::<4>(&v);
		assert!(res.is_err());
	}
}
