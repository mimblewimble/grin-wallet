// Copyright 2018 The Grin Developers
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

/// Standard Input/Output 'plugin' implementation
use std::io::{stdin, stdout, Read, Write};

use crate::base64;
use crate::config::WalletConfig;
use crate::libwallet::slate_versions::VersionedSlate;
use crate::libwallet::{Error, Slate};
use crate::WalletCommAdapter;
use std::collections::HashMap;

#[derive(Clone)]
pub struct StdioWalletCommAdapter {}

impl StdioWalletCommAdapter {
	/// Create
	pub fn new() -> Box<dyn WalletCommAdapter> {
		Box::new(StdioWalletCommAdapter {})
	}
}

impl WalletCommAdapter for StdioWalletCommAdapter {
	fn supports_sync(&self) -> bool {
		false
	}

	fn send_tx_sync(&self, _dest: &str, _slate: &Slate) -> Result<Slate, Error> {
		unimplemented!();
	}

	fn send_tx_async(&self, _dest: &str, slate: &Slate) -> Result<(), Error> {
		let mut stream = stdout();
		let v2 = VersionedSlate::V2(slate.into());
		let bytes = v2.encode()?;

		stream.write_all(base64::encode(&bytes).as_bytes())?;
		stream.flush()?;
		Ok(())
	}

	fn receive_tx_async(&self, params: &str) -> Result<Slate, Error> {
		let mut stream = stdin();
		let mut content = String::new();
		stream.read_to_string(&mut content)?;
		let bytes = base64::decode(content.as_bytes());
		Ok(Slate::deserialize_upgrade(&content)?) // TODO replace with slate.decode()
	}

	fn listen(
		&self,
		_params: HashMap<String, String>,
		_config: WalletConfig,
		_passphrase: &str,
		_account: &str,
		_node_api_secret: Option<String>,
	) -> Result<(), Error> {
		unimplemented!();
	}
}
