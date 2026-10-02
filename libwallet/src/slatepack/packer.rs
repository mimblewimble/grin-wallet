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

use super::armor::HEADER;
use crate::api_impl::owner::get_slatepack_secret_key;
use crate::slatepack::types::SlatepackAddressIndex;
use crate::{
	slatepack, Slate, SlateVersion, Slatepack, SlatepackAddress, SlatepackArmor, SlatepackBin,
	VersionedBinSlate, VersionedSlate,
};
use crate::{Error, NodeClient, WalletInst, WalletLCProvider};

use grin_keychain::Keychain;
use grin_util::secp::SecretKey;
use grin_util::Mutex;
use grin_wallet_util::byte_ser;

use std::convert::TryFrom;
use std::str;
use std::sync::Arc;

/// Arguments, mostly for encrypting decrypting a slatepack
pub struct SlatepackerArgs {
	/// Optional sender to include in slatepack
	pub sender: Option<SlatepackAddress>,
	/// Optional sender derivation path index
	pub sender_index: Option<SlatepackAddressIndex>,
	/// Optional list of recipients, for encryption
	pub recipients: Vec<SlatepackAddress>,
}

/// Helper struct to pack and unpack slatepacks
pub struct Slatepacker(SlatepackerArgs);

impl Slatepacker {
	/// Create with pathbuf and recipients
	pub fn new(args: SlatepackerArgs) -> Self {
		Self(args)
	}

	/// Deserialize provided data to slatepack
	pub fn deser_slatepack<'a, L, C, K>(
		&self,
		data: &[u8],
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		keychain_mask: Option<&SecretKey>,
		decrypt: bool,
	) -> Result<Slatepack, Error>
	where
		L: WalletLCProvider<'a, C, K>,
		C: NodeClient + 'a,
		K: Keychain + 'a,
	{
		// check if data is armored, if so, remove and continue
		let data_len = data.len() as u64;
		if data_len < slatepack::min_size() || data_len > slatepack::max_size() {
			return Err(Error::SlatepackDeser("Data invalid length".to_string()));
		}

		let test_header = &data[..HEADER.len()];

		let data = match str::from_utf8(test_header) {
			Ok(s) => {
				if s == HEADER {
					SlatepackArmor::decode(data)?
				} else {
					data.to_vec()
				}
			}
			Err(_) => data.to_vec(),
		};

		// try as bin first, then as json
		let mut slatepack = match byte_ser::from_bytes::<SlatepackBin>(&data) {
			Ok(s) => s.0,
			Err(e) => {
				debug!("Not a valid binary slatepack: {} - Will try JSON", e);
				let content = String::from_utf8(data).map_err(|e| {
					let msg = format!("{}", e);
					Error::SlatepackDeser(msg)
				})?;
				serde_json::from_str(&content).map_err(|e| {
					let msg = format!("Error reading JSON slatepack: {}", e);
					Error::SlatepackDeser(msg)
				})?
			}
		};

		slatepack.ver_check_warn();
		if decrypt {
			let mut err = None;
			for index in [
				Some(SlatepackAddressIndex(0)),
				slatepack.initial_sender_index.clone(),
				self.0.sender_index.clone(),
			] {
				if let Some(i) = index {
					let dec_key =
						get_slatepack_secret_key(wallet_inst.clone(), keychain_mask, i.clone())?;
					match slatepack.try_decrypt_payload(Some(&dec_key)) {
						Ok(_) => return Ok(slatepack),
						Err(e) => err = Some(e),
					}
				} else {
					continue;
				}
			}
			if let Some(e) = err {
				return Err(e);
			}
		}
		Ok(slatepack)
	}

	/// Create slatepack from slate and args
	pub fn create_slatepack(&self, slate: &Slate) -> Result<Slatepack, Error> {
		let out_slate = VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?;
		let bin_slate = VersionedBinSlate::try_from(out_slate).map_err(|_| Error::SlatepackSer)?;
		let mut slatepack = Slatepack::default();
		slatepack.payload = byte_ser::to_bytes(&bin_slate).map_err(|_| Error::SlatepackSer)?;
		slatepack.sender = self.0.sender.clone();
		slatepack.initial_sender_index = self.0.sender_index.clone();
		slatepack.try_encrypt_payload(self.0.recipients.clone())?;
		Ok(slatepack)
	}

	/// Armor a slatepack
	pub fn armor_slatepack(&self, slatepack: &Slatepack) -> Result<String, Error> {
		SlatepackArmor::encode(&slatepack)
	}
}
