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

use crate::libwallet::{Error, ErrorKind, Slate, SlateVersion, VersionedSlate};
use crate::{SlateGetter, SlatePutter};
use std::path::PathBuf;

#[derive(Clone)]
pub struct PathToSlate(pub PathBuf);

impl SlatePutter for PathToSlate {
	fn put_tx(&self, slate: &Slate) -> Result<(), Error> {
		let mut pub_tx = File::create(&self.0)?;
		let _r: crate::adapters::Reminder;
		let out_slate = {
			// TODO: This will need to be filled with any incompatibilities in the V4 Slate
			if false {
				warn!("Transaction contains features that require grin-wallet 4.0.0 or later");
				warn!("Please ensure the other party is running grin-wallet v4.0.0 or later before sending");
				VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?
			} else {
				let mut s = slate.clone();
				s.version_info.version = 3;
				s.version_info.orig_version = 3;
				VersionedSlate::into_version(s, SlateVersion::V3)?
			}
		};
		pub_tx.write_all(
			serde_json::to_string(&out_slate)
				.map_err(|_| ErrorKind::SlateSer)?
				.as_bytes(),
		)?;
		pub_tx.sync_all()?;
		Ok(())
	}
}

impl SlateGetter for PathToSlate {
	fn get_tx(&self) -> Result<Slate, Error> {
		let mut pub_tx_f = File::open(&self.0)?;
		let mut content = String::new();
		pub_tx_f.read_to_string(&mut content)?;
		Ok(Slate::deserialize_upgrade(&content)?)
	}
}
