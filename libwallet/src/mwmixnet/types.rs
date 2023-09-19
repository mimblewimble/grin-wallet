// Copyright 2022 The Grin Developers
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

//! Types related to mwmixnet requests required by rest of lib crate apis
//! Should rexport all needed types here

pub use super::onion::crypto::comsig::{self, ComSignature};
pub use super::onion::onion::Onion;
use serde::{Deserialize, Serialize};

/// A Swap request
#[derive(Serialize, Deserialize)]
pub struct SwapReq {
	onion: Onion,
	#[serde(with = "comsig::comsig_serde")]
	comsig: ComSignature,
}
