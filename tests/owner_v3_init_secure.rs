// Copyright 2021 The Grin Developers
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

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate grin_wallet;

use grin_wallet_api::{ECDHPubkey, JsonId};
use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

use clap::App;
use std::thread;
use std::time::Duration;

use grin_keychain::ExtKeychain;
use grin_util::secp::key::SecretKey;
use grin_util::{from_hex, static_secp_instance};
use grin_wallet_impls::DefaultLCProvider;
use serde_json;

#[macro_use]
mod common;
use common::{
	clean_output_dir, derive_ecdh_key, execute_command, initial_setup_wallet, instantiate_wallet,
	send_request, send_request_enc, setup, setup_global_chain_type, RetrieveSummaryInfoResp,
};

#[test]
fn owner_v3_init_secure() -> Result<(), grin_wallet_controller::Error> {
	setup_global_chain_type();

	let test_dir = "target/test_output/owner_v3_init_secure";
	setup(test_dir);

	// Create a new proxy to simulate server and wallet responses
	setup_proxy!(test_dir, chain, wallet1, client1, mask1, wallet2, client2, _mask2);

	// add some blocks manually
	let bh = 2u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// run a wallet owner listener
	let arg_vec = vec!["grin-wallet", "-p", "password", "owner_api", "-l", "33420"];
	thread::spawn(move || {
		let yml = load_yaml!("../src/bin/grin-wallet.yml");
		let app = App::from_yaml(yml);
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone()).unwrap();
	});
	thread::sleep(Duration::from_millis(200));

	// use in all tests
	let sec_key_str = "e00dcc4a009e3427c6b1e1a550c538179d46f3827a13ed74c759c860761caf1e";
	let _pub_key_str = "03b3c18c9a38783d105e238953b1638b021ba7456d87a5c085b3bdb75777b4c490";

	let sec_key_bytes = from_hex(sec_key_str).unwrap();
	let sec_key = {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		SecretKey::from_slice(&secp, &sec_key_bytes).unwrap()
	};

	// 1) Attempt to send an encrypted request before calling `init_secure_api`
	let req = include_str!("data/v3_reqs/retrieve_info.req.json");
	let res = send_request_enc::<String>(
		&JsonId::IntId(1),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req,
		&sec_key,
	)?;
	println!("RES 1: {:?}", res);
	assert!(res.is_err());
	assert_eq!(res.unwrap_err().code, -32001);

	// 2) Call any function on the V3 api without calling 'init_secure_api` first
	let res = send_request::<String>(1, "http://127.0.0.1:33420/v3/owner", &req)?;
	println!("RES 2: {:?}", res);
	assert!(res.is_err());
	assert_eq!(res.unwrap_err().code, -32001);

	// 3) Call 'init_secure_api' and negotiate shared key
	let req = include_str!("data/v3_reqs/init_secure_api.req.json");
	let res = send_request(1, "http://127.0.0.1:33420/v3/owner", req)?;
	println!("RES 3: {:?}", res);

	assert!(res.is_ok());
	let value: ECDHPubkey = res.unwrap();
	let shared_key = derive_ecdh_key(sec_key_str, &value.ecdh_pubkey);

	// 4) A normal request, correct key
	let req = include_str!("data/v3_reqs/retrieve_info.req.json");
	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 4: {:?}", res);
	assert!(res.is_ok());

	// 5) A normal request, incorrect key
	let mut bad_key = shared_key.clone();
	bad_key.0[0] = 0;
	let req = include_str!("data/v3_reqs/retrieve_info.req.json");
	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req,
		&bad_key,
	)?;
	println!("RES 5: {:?}", res);
	assert!(res.is_err());
	assert_eq!(res.unwrap_err().code, -32002);

	// 6) A malformed encrypted json request (missing nonce)
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "encrypted_request_v3",
		"params": {
			"body_enc:": "thisiswrong",
		}
	});
	let res = send_request::<String>(1, "http://127.0.0.1:33420/v3/owner", &req.to_string())?;
	println!("RES 6: {:?}", res);
	assert!(res.is_err());
	assert_eq!(res.unwrap_err().code, -32002);

	// 7) A malformed encrypted json request (garbage encrypted content)
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "encrypted_request_v3",
		"params": {
			"nonce": "32",
			"body_enc": "thisiswrong",
		}
	});
	let res = send_request::<String>(1, "http://127.0.0.1:33420/v3/owner", &req.to_string())?;
	println!("RES 7: {:?}", res);
	assert!(res.is_err());
	assert_eq!(res.unwrap_err().code, -32002);

	// 8) Encrypted call to `init_secure_api`, followed by re-deriving key
	let req = include_str!("data/v3_reqs/init_secure_api.req.json");
	let res = send_request_enc(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 8: {:?}", res);
	assert!(res.is_ok());
	let value: ECDHPubkey = res.unwrap();
	let shared_key = derive_ecdh_key(sec_key_str, &value.ecdh_pubkey);

	// 9) A normal request, with new correct key
	let req = include_str!("data/v3_reqs/retrieve_info.req.json");
	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 9: {:?}", res);
	assert!(res.is_ok());

	// 10) Call 'init_secure_api' unencrypted (which we can do) and negotiate new shared key
	let req = include_str!("data/v3_reqs/init_secure_api.req.json");
	let res = send_request(1, "http://127.0.0.1:33420/v3/owner", req)?;
	println!("RES 10: {:?}", res);

	assert!(res.is_ok());
	let value: ECDHPubkey = res.unwrap();
	let shared_key = derive_ecdh_key(sec_key_str, &value.ecdh_pubkey);

	// 11) A normal request, correct key
	let req = include_str!("data/v3_reqs/retrieve_info.req.json");
	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 11: {:?}", res);
	assert!(res.is_ok());

	// 12) A request which triggers an API error (not an encryption error)
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "method_dun_exist",
		"params": {
			"nope": "nope",
		}
	})
	.to_string();
	let res = send_request_enc::<String>(
		&JsonId::IntId(12),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 12: {:?}", res);
	assert!(res.is_err());
	assert_eq!(res.unwrap_err().code, -32601);

	// 13) A request which triggers an internal API error (not enough funds)
	let req = include_str!("data/v3_reqs/init_send_tx.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("13")),
		1,
		"http://127.0.0.1:33420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 13: {:?}", res);
	assert!(res.is_err());
	assert_eq!(res.unwrap_err().code, -32099);

	clean_output_dir(test_dir);

	Ok(())
}
