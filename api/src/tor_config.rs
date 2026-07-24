// Copyright 2026 The Grin Developers
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

use crate::config::TorConfig;
use crate::libwallet::Error;
use crate::util::Mutex;
use grin_wallet_config::config::get_global_config;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Shared path to the active wallet configuration.
#[doc(hidden)]
#[derive(Clone)]
pub struct ConfigPath(Arc<Mutex<PathBuf>>);

impl ConfigPath {
	pub(crate) fn get(&self) -> PathBuf {
		self.0.lock().clone()
	}

	pub(crate) fn set(&self, path: PathBuf) {
		*self.0.lock() = path;
	}
}

impl From<PathBuf> for ConfigPath {
	fn from(path: PathBuf) -> Self {
		Self(Arc::new(Mutex::new(path)))
	}
}

pub(crate) fn load(config_path: &Path) -> Result<TorConfig, Error> {
	Ok(get_global_config(config_path)?.tor_config())
}
