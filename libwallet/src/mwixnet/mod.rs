// Copyright 2023 The Grin Developers
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

//! Modules for mwixnet usage

pub mod onion;
pub use onion::{
	create_onion, onion::Onion, onion::OnionError, util as onion_util, ComSigError, ComSignature,
	MAX_MWIXNET_HOPS,
};

mod response;
pub use response::{parse_mwixnet_response, MwixnetError, MwixnetResponse};

mod types;
pub use types::{
	Hop, MixnetReqCreationParams, MwixnetReqCreationResult, MwixnetServerPublicKey, SwapReq,
};

mod client;
pub use client::{MwixnetClient, MwixnetClientImpl};
