// Copyright 2019 The Grin Developers
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

/// File Output 'plugin' implementation
use std::fs::File;
use std::io::{Read, Write};

use crate::client_utils::byte_ser;
use crate::libwallet::slate_versions::v3::SlateV3;
use crate::libwallet::slate_versions::v4::SlateV4;
use crate::libwallet::{
	Error, ErrorKind, Slate, SlateState, SlateVersion, VersionedBinSlate, VersionedSlate,
};
use crate::{SlateGetter, SlatePutter};
use std::convert::TryFrom;
use std::path::PathBuf;

#[derive(Clone)]
pub struct PathToSlate(pub PathBuf);

impl SlatePutter for PathToSlate {
	fn put_tx(&self, slate: &Slate, as_bin: bool) -> Result<(), Error> {
		// For testing (output raw slate data for reference)
		/*{
			let mut raw_path = self.0.clone();
			raw_path.set_extension("raw");
			let mut raw_slate = File::create(&raw_path)?;
			raw_slate.write_all(&format!("{:?}", slate).as_bytes())?;
			raw_slate.sync_all()?;
		}*/
		let mut pub_tx = File::create(&self.0)?;
		// TODO:
		let out_slate = {
			// TODO: Remove post HF3
			if slate.version_info.version == 2 || slate.version_info.version == 3 {
				// if the slate we read in in V3 or 2 (holdover from 3.0.0), output a slate V3,
				// which can be read by v3.x wallets
				let v4_slate = SlateV4::from(slate.clone());
				let mut v3_slate = SlateV3::try_from(&v4_slate)?;
				// Fill in V3 participant IDs according to state
				if slate.state == SlateState::Invoice1 {
					for mut e in v3_slate.participant_data.iter_mut() {
						if Some(e.public_blind_excess.clone()) == slate.participant_id {
							e.id = 1;
						} else {
							e.id = 0;
						}
					}
				}
				if slate.state == SlateState::Invoice2 {
					for mut e in v3_slate.participant_data.iter_mut() {
						if Some(e.public_blind_excess.clone()) == slate.participant_id {
							e.id = 0;
						} else {
							e.id = 1;
						}
					}
				}
				if slate.state == SlateState::Standard1 {
					for mut e in v3_slate.participant_data.iter_mut() {
						if Some(e.public_blind_excess.clone()) == slate.participant_id {
							e.id = 0;
						} else {
							e.id = 1;
						}
					}
				}
				if slate.state == SlateState::Standard2 {
					for mut e in v3_slate.participant_data.iter_mut() {
						if Some(e.public_blind_excess.clone()) == slate.participant_id {
							e.id = 1;
						} else {
							e.id = 0;
						}
					}
				}
				v3_slate.version_info.version = 3;
				VersionedSlate::V3(v3_slate)
			} else {
				VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?
			}
		};
		if as_bin {
			let bin_slate =
				VersionedBinSlate::try_from(out_slate).map_err(|_| ErrorKind::SlateSer)?;
			pub_tx.write_all(&byte_ser::to_bytes(&bin_slate).map_err(|_| ErrorKind::SlateSer)?)?;
		} else {
			pub_tx.write_all(
				serde_json::to_string_pretty(&out_slate)
					.map_err(|_| ErrorKind::SlateSer)?
					.as_bytes(),
			)?;
		}
		pub_tx.sync_all()?;
		Ok(())
	}
}

impl SlateGetter for PathToSlate {
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
