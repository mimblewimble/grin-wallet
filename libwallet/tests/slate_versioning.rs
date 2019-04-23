// Copyright 2019 The Grin Developers
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

//! core::libtx specific tests
use grin_wallet_libwallet::Slate;

// test all slate conversions
#[test]
fn slate_conversions() {
	// Test V0 to V2
	let v0 = include_str!("slates/v0.slate");
	let res = Slate::deserialize_upgrade(&v0);
	assert!(res.is_ok());
	// should serialize as latest
	let res = res.unwrap();
	assert_eq!(res.version_info.orig_version, 0);
	let s = res.serialize_to_version(Some(2));
	assert!(s.is_ok());
	println!("v0 -> v2: {}", s.unwrap());

	// Test V1 to V2
	let v1 = include_str!("slates/v1.slate");
	let res = Slate::deserialize_upgrade(&v1);
	assert!(res.is_ok());
	// should serialize as latest
	let res = res.unwrap();
	assert_eq!(res.version_info.orig_version, 1);
	let s = res.serialize_to_version(Some(2));
	assert!(s.is_ok());
	println!("v1 -> v2: {}", s.unwrap());

	// V2 -> V2, check version
	let v2 = include_str!("slates/v2.slate");
	let res = Slate::deserialize_upgrade(&v2);
	assert!(res.is_ok());
	let res = res.unwrap().serialize_to_version(Some(2));
	let s = res.unwrap();
	let res = Slate::deserialize_upgrade(&s).unwrap();
	assert_eq!(res.version_info.orig_version, 2);

	// Downgrade to V1
	let v2 = include_str!("slates/v2.slate");
	let res = Slate::deserialize_upgrade(&v2);
	assert!(res.is_ok());
	// downgrade
	let s = res.unwrap().serialize_to_version(Some(1));
	assert!(s.is_ok());
	println!("v2 -> v1: {}", s.unwrap());

	// Downgrade to V0
	let v2 = include_str!("slates/v2.slate");
	let res = Slate::deserialize_upgrade(&v2);
	assert!(res.is_ok());
	// downgrade
	let s = res.unwrap().serialize_to_version(Some(0));
	assert!(s.is_ok());
	println!("v2 -> v0: {}", s.unwrap());
}
