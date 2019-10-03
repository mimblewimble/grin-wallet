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

use crate::libwallet::{Error, ErrorKind, Slate};
use crate::{SlateGetter, SlatePutter};
use std::path::PathBuf;

#[derive(Clone)]
pub struct PathToSlate(pub PathBuf);

impl SlatePutter for PathToSlate {
	fn put_tx(&self, slate: &Slate) -> Result<(), Error> {
		let mut pub_tx = File::create(&self.0)?;
		pub_tx.write_all(
			serde_json::to_string(slate)
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
