// Copyright 2024 The Grin Developers
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

//! Types related to mwixnet requests required by rest of lib crate apis
//! Should rexport all needed types here

use super::onion::comsig_serde;
use grin_core::libtx::secp_ser::string_or_u64;
use grin_util::secp::key::SecretKey;
use serde::{Deserialize, Serialize};

pub use super::onion::{onion::Onion, ComSignature, Hop};

/// A Swap request
#[derive(Serialize, Deserialize, Debug)]
pub struct SwapReq {
	/// Com signature
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
	/// Onion
	pub onion: Onion,
}

/// mwixnetRequest Creation Params
#[derive(Serialize, Deserialize, Debug)]
pub struct MixnetReqCreationParams {
	/// List of all the server keys
	pub server_keys: Vec<SecretKey>,
	/// Fees per hop
	#[serde(with = "string_or_u64")]
	pub fee_per_hop: u64,
}
