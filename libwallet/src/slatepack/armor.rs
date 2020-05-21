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

// A note on encoding efficiency: 0.75 for Base64, 0.744 for Base62, 0.732 for Base58
// slatepack uses a modified Base58Check encoding to create armored slate payloads:
// 1. Take first four bytes of SHA256(SHA256(slate.as_bytes()))
// 2. Concatenate result of step 1 and slate.as_bytes()
// 3. Base58 encode bytes from step 2
// Finally add armor framing and space/newline formatting as desired

use crate::{Error, ErrorKind};
use grin_wallet_util::byte_ser;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::str;

use super::types::{Slatepack, SlatepackBin};

// Framing and formatting for slate armor
static HEADER: &str = "BEGINSLATEPACK. ";
static FOOTER: &str = ". ENDSLATEPACK.";
const WORD_LENGTH: usize = 15;

lazy_static! {
	static ref HEADER_REGEX: Regex =
		Regex::new(concat!(r"^[>\n\r\t ]*BEGINSLATEPACK[>\n\r\t ]*$")).unwrap();
	static ref FOOTER_REGEX: Regex =
		Regex::new(concat!(r"^[>\n\r\t ]*ENDSLATEPACK[>\n\r\t ]*$")).unwrap();
	static ref WHITESPACE_LIST: [u8; 5] = [b'>', b'\n', b'\r', b'\t', b' '];
}

/// Wrapper for associated functions
pub struct SlatepackArmor;

impl SlatepackArmor {
	/// Decode an armored Slatepack
	pub fn decode(data: &str) -> Result<Vec<u8>, Error> {
		// Convert the armored slate to bytes for parsing
		let armor_bytes: Vec<u8> = data.as_bytes().to_vec();
		// Collect the bytes up to the first period, this is the header
		let header_bytes = &armor_bytes
			.iter()
			.take_while(|byte| **byte != b'.')
			.cloned()
			.collect::<Vec<u8>>();
		// Verify the header...
		check_header(&header_bytes)?;
		// Get the length of the header
		let header_len = *&header_bytes.len() + 1;
		// Skip the length of the header to read for the payload until the next period
		let payload_bytes = &armor_bytes[header_len as usize..]
			.iter()
			.take_while(|byte| **byte != b'.')
			.cloned()
			.collect::<Vec<u8>>();
		// Get length of the payload to check the footer framing
		let payload_len = *&payload_bytes.len();
		// Get footer bytes and verify them
		let consumed_bytes = header_len + payload_len + 1;
		let footer_bytes = &armor_bytes[consumed_bytes as usize..]
			.iter()
			.take_while(|byte| **byte != b'.')
			.cloned()
			.collect::<Vec<u8>>();
		check_footer(&footer_bytes)?;
		// Clean up the payload bytes to be deserialized
		let clean_payload = &payload_bytes
			.iter()
			.filter(|byte| !WHITESPACE_LIST.contains(byte))
			.cloned()
			.collect::<Vec<u8>>();
		// Decode payload from base58
		let base_decode = bs58::decode(&clean_payload).into_vec().unwrap();
		let error_code = &base_decode[0..4];
		let slatepack_bytes = &base_decode[4..];
		// Make sure the error check code is valid for the slate data
		error_check(&error_code.to_vec(), &slatepack_bytes.to_vec())?;
		// Return slate as binary or string
		/*let slatepack_bin = byte_ser::from_bytes::<SlatepackBin>(&slate_bytes).map_err(|e| {
			error!("Error reading JSON Slatepack: {}", e);
			ErrorKind::SlatepackDeser
		})?;*/
		Ok(slatepack_bytes.to_vec())
	}

	/// Encode an armored slatepack
	pub fn encode(slatepack: &Slatepack, num_cols: usize) -> Result<String, Error> {
		let slatepack_bytes = byte_ser::to_bytes(&SlatepackBin(slatepack.clone()))
			.map_err(|_| ErrorKind::SlatepackSer)?;
		let encoded_slatepack = base58check(&slatepack_bytes)?;
		let formatted_slatepack = format_slatepack(&encoded_slatepack, num_cols)?;
		Ok(format!("{}{}{}\n", HEADER, formatted_slatepack, FOOTER))
	}
}

// Takes an error check code and a slate binary and verifies that the code was generated from slate
fn error_check(error_code: &Vec<u8>, slate_bytes: &Vec<u8>) -> Result<(), Error> {
	let new_check = generate_check(&slate_bytes)?;
	if error_code.iter().eq(new_check.iter()) {
		Ok(())
	} else {
		Err(ErrorKind::InvalidSlatepackData(
			"Bad slate error code- some data was corrupted".to_string(),
		)
		.into())
	}
}

// Checks header framing bytes and returns an error if they are invalid
fn check_header(header: &Vec<u8>) -> Result<(), Error> {
	let framing = str::from_utf8(&header).unwrap();
	if HEADER_REGEX.is_match(framing) {
		Ok(())
	} else {
		Err(ErrorKind::InvalidSlatepackData("Bad armor header".to_string()).into())
	}
}

// Checks footer framing bytes and returns an error if they are invalid
fn check_footer(footer: &Vec<u8>) -> Result<(), Error> {
	let framing = str::from_utf8(&footer).unwrap();
	if FOOTER_REGEX.is_match(framing) {
		Ok(())
	} else {
		Err(ErrorKind::InvalidSlatepackData("Bad armor footer".to_string()).into())
	}
}

// MODIFIED Base58Check encoding for slate bytes
fn base58check(slate: &[u8]) -> Result<String, Error> {
	// Serialize the slate json string to a vector of bytes
	let mut slate_bytes: Vec<u8> = slate.to_vec();
	// Get the four byte checksum for the slate binary
	let mut check_bytes: Vec<u8> = generate_check(&slate_bytes)?;
	// Make a new buffer and concatenate checksum bytes and slate bytes
	let mut slate_buf = Vec::new();
	slate_buf.append(&mut check_bytes);
	slate_buf.append(&mut slate_bytes);
	// Encode the slate buffer containing the slate binary and checksum bytes as Base58
	let b58_slate = bs58::encode(slate_buf).into_string();
	Ok(b58_slate)
}

// Adds human readable formatting to the slate payload for armoring
fn format_slatepack(slatepack: &str, num_cols: usize) -> Result<String, Error> {
	let formatter = slatepack
		.chars()
		.enumerate()
		.flat_map(|(i, c)| {
			if i != 0 && i % WORD_LENGTH == 0 {
				if num_cols != 0 && i % (WORD_LENGTH * num_cols) == WORD_LENGTH * 2 {
					Some('\n')
				} else {
					Some(' ')
				}
			} else {
				None
			}
			.into_iter()
			.chain(std::iter::once(c))
		})
		.collect::<String>();
	Ok(formatter)
}

// Returns the first four bytes of a double sha256 hash of some bytes
fn generate_check(payload: &Vec<u8>) -> Result<Vec<u8>, Error> {
	let mut first_hash = Sha256::new();
	first_hash.input(payload);
	let mut second_hash = Sha256::new();
	second_hash.input(first_hash.result());
	let checksum = second_hash.result();
	let check_bytes: Vec<u8> = checksum[0..4].to_vec();
	Ok(check_bytes)
}
