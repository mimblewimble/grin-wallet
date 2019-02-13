// Copyright 2018 The Grin Developers
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
		"[wallet]".to_string(),
		"
#########################################
### WALLET CONFIGURATION              ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"api_listen_interface".to_string(),
		"
#host IP for wallet listener, change to \"0.0.0.0\" to receive grins
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
		"keybase_notify_ttl".to_string(),
		"
#The exploding lifetime for keybase notification on coins received.
#Unit: Minute. Default value 1440 minutes for one day.
#Refer to https://keybase.io/blog/keybase-exploding-messages for detail.
#To disable this notification, set it as 0.
"
		.to_string(),
	);

	retval.insert(
		"[logging]".to_string(),
		"
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

	retval
}

fn get_key(line: &str) -> String {
	if line.contains("[") && line.contains("]") {
		return line.to_owned();
	} else if line.contains("=") {
		return line.split("=").collect::<Vec<&str>>()[0].trim().to_owned();
	} else {
		return "NOT_FOUND".to_owned();
	}
}

pub fn insert_comments(orig: String) -> String {
	let comments = comments();
	let lines: Vec<&str> = orig.split("\n").collect();
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
	ret_val.to_owned()
}
