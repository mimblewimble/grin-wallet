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
//use grin_wallet_api::foreign_rpc_client;
use grin_wallet_api::run_doctest_foreign;
//use grin_wallet_libwallet::VersionedSlate;
use serde_json;
use serde_json::Value;
use tempfile::tempdir;
//use grin_wallet_libwallet::slate_versions::v1::SlateV1;
//use grin_wallet_libwallet::slate_versions::v2::SlateV2;

// test all slate conversions
//#[test]
fn _receive_versioned_slate() {
	// as in doctests, except exercising versioning functionality
	// by accepting and responding with a V1 slate

	let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	let dir = dir
		.path()
		.to_str()
		.ok_or("Failed to convert tmpdir path to string.".to_owned())
		.unwrap();

	let v1_req = include_str!("slates/v1_req.slate");
	let v1_resp = include_str!("slates/v1_res.slate");

	// leave here for the ability to create earlier slate versions
	// for test input
	/*let v: Value = serde_json::from_str(v1_req).unwrap();
	let v2_slate = v["params"][0].clone();
	println!("{}", v2_slate);
	let v2_slate_str = v2_slate.to_string();
	println!("{}", v2_slate_str);
	let v2: SlateV2 = serde_json::from_str(&v2_slate.to_string()).unwrap();
	let v1 = SlateV1::from(v2);
	let v1_str = serde_json::to_string_pretty(&v1).unwrap();
	panic!("{}", v1_str);*/

	let request_val: Value = serde_json::from_str(v1_req).unwrap();
	let expected_response: Value = serde_json::from_str(v1_resp).unwrap();

	let response = run_doctest_foreign(request_val, dir, 5, true, false)
		.unwrap()
		.unwrap();

	if response != expected_response {
		panic!(
			"(left != right) \nleft: {}\nright: {}",
			serde_json::to_string_pretty(&response).unwrap(),
			serde_json::to_string_pretty(&expected_response).unwrap()
		);
	}
}

// TODO: Re-introduce on a new slate version

/*
/// call ForeignRpc::receive_tx on vs and return the result
fn receive_tx(vs: VersionedSlate) -> VersionedSlate {
	let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	let dir = dir
		.path()
		.to_str()
		.ok_or("Failed to convert tmpdir path to string.".to_owned())
		.unwrap();
	let bound_method = foreign_rpc_client::receive_tx(
		vs,
		None,
		Some("Thanks for saving my dog from that tree, bddap.".into()),
	)
	.unwrap();
	let (call, tracker) = bound_method.call();
	let json_response = run_doctest_foreign(call.as_request(), dir, 5, false, false)
		.unwrap()
		.unwrap();
	let mut response = easy_jsonrpc::Response::from_json_response(json_response).unwrap();
	tracker.get_return(&mut response).unwrap().unwrap()
}

#[test]
fn version_unchanged() {
	let req: Value = serde_json::from_str(include_str!("slates/v1_req.slate")).unwrap();
	let slate: VersionedSlate = serde_json::from_value(req["params"][0].clone()).unwrap();
	let slate_req: Slate = slate.into();

	assert_eq!(
		receive_tx(VersionedSlate::into_version(
			slate_req.clone(),
			SlateVersion::V0
		))
		.version(),
		SlateVersion::V0
	);

	assert_eq!(
		receive_tx(VersionedSlate::into_version(
			slate_req.clone(),
			SlateVersion::V1
		))
		.version(),
		SlateVersion::V1
	);

	assert_eq!(
		receive_tx(VersionedSlate::into_version(
			slate_req.clone(),
			SlateVersion::V2
		))
		.version(),
		SlateVersion::V2
	);

	// compile time test will remind us to update these tests when updating slate format
	fn _all_versions_tested(vs: VersionedSlate) {
		match vs {
			VersionedSlate::V0(_) => (),
			VersionedSlate::V1(_) => (),
			VersionedSlate::V2(_) => (),
		}
	}
}*/
