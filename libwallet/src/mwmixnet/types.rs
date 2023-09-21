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
pub use super::onion::crypto::secp::{add_excess, random_secret};
pub use super::onion::onion::Onion;
pub use super::onion::{new_hop, Hop};
use crate::grin_util::secp::key::SecretKey;
use serde::{Deserialize, Serialize};

/// A Swap request
#[derive(Serialize, Deserialize)]
pub struct SwapReq {
	/// Com signature
	#[serde(with = "comsig::comsig_serde")]
	pub comsig: ComSignature,
	/// Onion
	pub onion: Onion,
}

/// MWMixnetRequest Creation Params

pub struct MixnetReqCreationParams {
	/// List of all the server keys
	pub server_keys: Vec<SecretKey>,
	/// Fees per hop
	pub fee_per_hop: u32,
}
