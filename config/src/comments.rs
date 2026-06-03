// Copyright 2021 The Grin Developers
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

//! Comments for configuration + injection into output .toml
use std::collections::HashMap;

/// maps entries to Comments that should precede them
fn comments() -> HashMap<String, String> {
	let mut retval = HashMap::new();

	retval.insert(
		"config_file_version".to_string(),
		"
#Version of the Generated Configuration File for the Grin Wallet (DO NOT EDIT)
"
		.to_string(),
	);

	retval.insert(
		"[wallet]".to_string(),
		"
#########################################
### WALLET CONFIGURATION              ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"api_listen_port".to_string(),
		"
#path of TLS certificate file, self-signed certificates are not supported
#tls_certificate_file = \"\"
#private key for the TLS certificate
#tls_certificate_key = \"\"

#port for wallet listener
"
		.to_string(),
	);

	retval.insert(
		"owner_api_listen_port".to_string(),
		"
#port for wallet owner api
"
		.to_string(),
	);

	retval.insert(
		"api_secret_path".to_string(),
		"
#path of the secret token used by the API to authenticate the calls
#comment it to disable basic auth
"
		.to_string(),
	);
	retval.insert(
		"check_node_api_http_addr".to_string(),
		"
#where the wallet should find a running node
"
		.to_string(),
	);
	retval.insert(
		"node_api_secret_path".to_string(),
		"
#location of the node api secret for basic auth on the Grin API
"
		.to_string(),
	);
	retval.insert(
		"owner_api_include_foreign".to_string(),
		"
#include the foreign API endpoints on the same port as the owner
#API. Useful for networking environments like AWS ECS that make
#it difficult to access multiple ports on a single service.
"
		.to_string(),
	);
	retval.insert(
		"data_file_dir".to_string(),
		"
#where to find wallet files (seed, data, etc)
"
		.to_string(),
	);
	retval.insert(
		"no_commit_cache".to_string(),
		"
#If true, don't store calculated commits in the database
#better privacy, but at a performance cost of having to
#re-calculate commits every time they're used
"
		.to_string(),
	);
	retval.insert(
		"dark_background_color_scheme".to_string(),
		"
#Whether to use the black background color scheme for command line
"
		.to_string(),
	);
	retval.insert(
		"accept_fee_base".to_string(),
		"
#Minimum acceptable fee per unit of transaction weight
"
		.to_string(),
	);
	retval.insert(
		"[logging]".to_string(),
		"
#Type of proxy, eg \"socks4\", \"socks5\", \"http\", \"https\"
#transport = \"https\"

#Proxy address, eg IP:PORT or Hostname
#server = \"\"

#Username for the proxy server authentification
#user = \"\"

#Password for the proxy server authentification
#pass = \"\"

#This computer goes through a firewall that only allows connections to certain ports (Optional)
#allowed_port = [80, 443]


#########################################
### LOGGING CONFIGURATION             ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"log_to_stdout".to_string(),
		"
#whether to log to stdout
"
		.to_string(),
	);

	retval.insert(
		"stdout_log_level".to_string(),
		"
#log level for stdout: Error, Warning, Info, Debug, Trace
"
		.to_string(),
	);

	retval.insert(
		"log_to_file".to_string(),
		"
#whether to log to a file
"
		.to_string(),
	);

	retval.insert(
		"file_log_level".to_string(),
		"
#log level for file: Error, Warning, Info, Debug, Trace
"
		.to_string(),
	);

	retval.insert(
		"log_file_path".to_string(),
		"
#log file path
"
		.to_string(),
	);

	retval.insert(
		"log_file_append".to_string(),
		"
#whether to append to the log file (true), or replace it on every run (false)
"
		.to_string(),
	);

	retval.insert(
		"log_max_size".to_string(),
		"
#maximum log file size in bytes before performing log rotation
#comment it to disable log rotation
"
		.to_string(),
	);

	retval.insert(
		"[tor]".to_string(),
		"
#########################################
### TOR CONFIGURATION (Experimental)  ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"skip_send_attempt".to_string(),
		"
#Whether to skip send attempts (used for debugging) 
"
		.to_string(),
	);

	retval.insert(
		"use_tor_listener".to_string(),
		"
#Whether to start tor listener on listener startup (default true)
"
		.to_string(),
	);

	retval.insert(
		"socks_proxy_addr".to_string(),
		"
#Address of the running TOR (SOCKS) server
"
		.to_string(),
	);

	retval.insert(
		"send_config_dir".to_string(),
		"
#Directory to output TOR configuration to when sending
"
		.to_string(),
	);

	retval.insert(
		"[tor.bridge]".to_string(),
		"
#########################################
### TOR BRIDGE                        ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"[tor.proxy]".to_string(),
		"
#Tor bridge relay: allow to send and receive via TOR in a country where it is censored.
#Enable it by entering a single bridge line. To disable it, you must comment it.
#Support of the transport: obfs4, meek and snowflake. 
#obfs4proxy or snowflake client binary must be installed and on your path.
#For example, the bridge line must be in the following format for obfs4 transport: \"obfs4 [IP:PORT] [FINGERPRINT] cert=[CERT] iat-mode=[IAT-MODE]\"
#bridge_line = \"\"

#Plugging client option, needed only for snowflake (let it empty if you want to use the default option of tor) or debugging purpose
#client_option = \"\"


#########################################
### TOR PROXY                         ###
#########################################
"
	.to_string(),
	);

	retval
}

fn get_key(line: &str) -> String {
	if line.contains('[') && line.contains(']') {
		line.to_owned()
	} else if line.contains('=') {
		line.split('=').collect::<Vec<&str>>()[0].trim().to_owned()
	} else {
		"NOT_FOUND".to_owned()
	}
}

pub fn insert_comments(orig: String) -> String {
	let comments = comments();
	let lines: Vec<&str> = orig.split('\n').collect();
	let mut out_lines = vec![];
	for l in lines {
		let key = get_key(l);
		if let Some(v) = comments.get(&key) {
			out_lines.push(v.to_owned());
		}
		out_lines.push(l.to_owned());
		out_lines.push("\n".to_owned());
	}
	let mut ret_val = String::from("");
	for l in out_lines {
		ret_val.push_str(&l);
	}
	ret_val
}

pub fn migrate_comments(
	old_config: String,
	new_config: String,
	old_version: Option<u32>,
) -> String {
	let comments = comments();
	// Prohibe the key we are basing on to introduce new comments for [tor.proxy]
	let prohibited_key = match old_version {
		None => vec!["[logging]"],
		Some(_) => vec![],
	};
	let mut vec_old_conf = vec![];
	let mut hm_key_cmt_old = HashMap::new();
	let old_conf: Vec<&str> = old_config.split_inclusive('\n').collect();
	// collect old key in a vec and insert old key/comments from the old conf in a hashmap
	let vec_key_old = old_conf
		.iter()
		.filter_map(|line| {
			let line_nospace = line.trim();
			let is_ascii_control = line_nospace.chars().all(|x| x.is_ascii_control());
			match line.contains("#") || is_ascii_control {
				true => {
					vec_old_conf.push(line.to_owned());
					None
				}
				false => {
					let comments: String = vec_old_conf.iter().flat_map(|s| s.chars()).collect();
					let key = get_key(line_nospace);
					match key != "NOT_FOUND" {
						true => {
							vec_old_conf.clear();
							hm_key_cmt_old.insert(key.clone(), comments);
							Some(key)
						}
						false => None,
					}
				}
			}
		})
		.collect::<Vec<String>>();

	let new_conf: Vec<&str> = new_config.split_inclusive('\n').collect();
	// collect new key and the whole key line from the new config
	let vec_key_cmt_new = new_conf
		.iter()
		.filter_map(|line| {
			let line_nospace = line.trim();
			let is_ascii_control = line_nospace.chars().all(|x| x.is_ascii_control());
			match !line.contains("#") && !is_ascii_control {
				true => {
					let key = get_key(line_nospace);
					match key != "NOT_FOUND" {
						true => Some((key, line_nospace.to_string())),
						false => None,
					}
				}
				false => None,
			}
		})
		.collect::<Vec<(String, String)>>();

	let mut new_config_str = String::from("");
	// Merging old comments in the new config (except if the key is contained in the prohibited vec) with all new introduced key comments
	for (key, key_line) in vec_key_cmt_new {
		let old_key_exist = vec_key_old.iter().any(|old_key| *old_key == key);
		let key_fmt = format!("{}\n", key_line);
		if old_key_exist {
			if prohibited_key.contains(&key.as_str()) {
				// push new config key/comments
				let value = comments.get(&key).unwrap();
				new_config_str.push_str(value);
				new_config_str.push_str(&key_fmt);
			} else {
				// push old config key/comment
				let value = hm_key_cmt_old.get(&key).unwrap();
				new_config_str.push_str(value);
				new_config_str.push_str(&key_fmt);
			}
		} else {
			// old key does not exist, we push new key/comments
			let value = comments.get(&key).unwrap();
			new_config_str.push_str(value);
			new_config_str.push_str(&key_fmt);
		}
	}
	new_config_str
}
