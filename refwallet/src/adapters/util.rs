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

use crate::libwallet::slate::{Slate, VersionedSlate};
use crate::libwallet::slate_versions::v0::SlateV0;
use crate::libwallet::ErrorKind;
use serde_json as json;

pub fn get_versioned_slate(slate: &Slate) -> VersionedSlate {
	let slate = slate.clone();
	match slate.version {
		0 => VersionedSlate::V0(SlateV0::from(slate)),
		_ => VersionedSlate::V1(slate),
	}
}

pub fn serialize_slate(slate: &Slate) -> String {
	let vs = get_versioned_slate(slate);
	error!("versioned slate: {:?}", vs);
	//json::to_string(&get_versioned_slate(vs)).unwrap()
	let json_vs = json::to_string(&vs).unwrap();
	error!("jsoned slate: {}", json_vs);
	//json::to_string(&vs).unwrap()
	json_vs
}

pub fn deserialize_slate(raw_slate: &str) -> Slate {
	let versioned_slate: VersionedSlate = json::from_str(&raw_slate)
		.map_err(|err| ErrorKind::Format(err.to_string()))
		.unwrap();
	versioned_slate.into()
}
