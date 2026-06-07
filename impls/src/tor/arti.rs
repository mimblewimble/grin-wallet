// Copyright 2026 The Grin Developers
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

use crate::tor::Tor;
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use arti_ed25519_dalek::hazmat::ExpandedSecretKey;
use bytes::Bytes;
use curve25519_dalek::digest::Digest;
use fs_mistrust::Mistrust;
use grin_util::secp::SecretKey;
use grin_wallet_config::TorConfig;
use grin_wallet_libwallet::Error;
use grin_wallet_util::OnionV3Address;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use sha2::Sha512;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsrproxy::config::{
	Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier, HsNickname};
use tor_keymgr::config::CfgPath;
use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder, KeystoreSelector};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tor_rtcompat::ToplevelBlockOn;

/// Start Tor service from provided key.
pub fn start_tor_service(
	key: SecretKey,
	tor_dir: &str,
	addr: &str,
	config: TorConfig,
) -> Result<Tor, Error> {
	let state_path = Path::new(&tor_dir).join("state");
	let cache_path = Path::new(&tor_dir).join("cache");
	let (client, config) = init_client(&state_path, &cache_path, config)?;

	// Add service key to keystore.
	let onion_address =
		OnionV3Address::from_private(&key.0).map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
	let hs = HsNickname::new(onion_address.to_string()).unwrap();
	let keystore_path = Path::new(&state_path).join("keystore");
	let _ = add_service_key(config.fs_mistrust(), &key, &hs, keystore_path)
		.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;

	// Launch Onion service.
	let service_config = OnionServiceConfigBuilder::default()
		.nickname(hs.clone())
		.build()
		.unwrap();
	let running_onion_service = match client.launch_onion_service(service_config) {
		Ok(res) => {
			if let Some((service, request)) = res {
				// Launch service proxy.
				let addr: SocketAddr = addr
					.parse()
					.map_err(|e| Error::TorProcess(format!("{:?}", e)))?;
				let c = client.clone();
				thread::spawn(move || {
					c.clone().runtime().block_on(async move {
						match run_service_proxy(c, addr, request, hs.clone()).await {
							Ok(_) => info!("Tor proxy stopped"),
							Err(e) => error!("Tor proxy error: {:?}", e),
						}
					})
				});
				service
			} else {
				return Err(Error::TorProcess("Can not launch onion service".to_owned()));
			}
		}
		Err(e) => return Err(Error::TorProcess(format!("{:?}", e))),
	};
	Ok(Tor {
		process: None,
		service: Some(running_onion_service),
		client: Some(client),
	})
}

/// Start Tor client to send requests.
pub fn start_tor_client(tor_dir: &str, config: TorConfig) -> Result<Tor, Error> {
	let state_path = Path::new(tor_dir).join("state");
	let cache_path = Path::new(tor_dir).join("cache");
	let (client, _) = init_client(&state_path, &cache_path, config)?;
	Ok(Tor {
		process: None,
		service: None,
		client: Some(client),
	})
}

/// Make POST request with provided client.
pub fn tor_post<IN>(
	client: TorClient<TokioNativeTlsRuntime>,
	input: &IN,
	url: &str,
) -> Result<String, Error>
where
	IN: Serialize,
{
	let json = serde_json::to_string(input)
		.map_err(|_| Error::GenericError("Could not serialize data to JSON".to_owned()))?;
	let url = url.to_string();
	let url: Uri = url
		.parse()
		.map_err(|_| Error::GenericError("Bad URL".to_owned()))?;
	let res: Result<String, Error> = thread::spawn(move || {
		let c = client.clone();
		client.runtime().block_on(async move {
			let stream = c
				.connect((url.host().unwrap(), url.port_u16().unwrap_or(80)))
				.await
				.map_err(|e| Error::TorProcess(format!("{:?}", e)))?;
			let (mut request_sender, connection) =
				hyper::client::conn::http1::handshake(TokioIo::new(stream))
					.await
					.map_err(|e| Error::TorProcess(format!("{:?}", e)))?;

			// Spawn a task to poll the connection and drive the HTTP state.
			tokio::spawn(async move {
				connection.await.unwrap();
			});

			let resp = request_sender
				.send_request(
					Request::builder()
						.uri(url)
						.method("POST")
						.body::<Full<Bytes>>(Full::from(json))
						.map_err(|e| Error::TorProcess(format!("{:?}", e)))?,
				)
				.await
				.map_err(|e| Error::TorProcess(format!("{:?}", e)))?;

			let body_resp = resp
				.into_body()
				.collect()
				.await
				.map_err(|e| Error::TorProcess(format!("{:?}", e)))?;
			let body = body_resp.to_bytes().into();
			let body_text =
				String::from_utf8(body).map_err(|e| Error::TorProcess(format!("{:?}", e)))?;
			Ok(body_text)
		})
	})
	.join()
	.unwrap();
	res
}

/// Create Tor client.
fn init_client(
	state_path: &PathBuf,
	cache_path: &PathBuf,
	config: TorConfig,
) -> Result<(TorClient<TokioNativeTlsRuntime>, TorClientConfig), Error> {
	let mut builder = TorClientConfigBuilder::from_directories(&state_path, cache_path);
	builder.address_filter().allow_onion_addrs(true);

	// Configure bridge.
	if let Some(bridge_line) = config.bridge.bridge_line {
		let bridge: BridgeConfigBuilder = bridge_line
			.parse()
			.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
		builder.bridges().bridges().push(bridge.clone());
		match bridge.get_transport() {
			None => {
				return Err(Error::TorConfig(format!(
					"No transport found at {}",
					bridge_line
				)))
			}
			Some(t) => {
				// Now configure bridge transport. (Requires the "pt-client" feature)
				let bin_path = config.bridge.bridge_bin_path.unwrap_or(t.to_owned());
				let mut transport = TransportConfigBuilder::default();
				transport
					.protocols(vec![t
						.parse()
						.map_err(|e| Error::TorConfig(format!("{:?}", e)))?])
					.path(CfgPath::new(bin_path))
					.run_on_startup(true);
				builder.bridges().transports().push(transport);
			}
		}
	}
	let config = builder.build().map_err(|e| Error::TorConfig(format!("{:?}", e)))?;

	// Launch client.
	let runtime = TokioNativeTlsRuntime::create()?;
	let client = TorClient::with_runtime(runtime.clone())
		.config(config.clone())
		.create_unbootstrapped()
		.map_err(|e| Error::TorProcess(format!("{:?}", e)))?;
	let c = client.clone();
	let r = runtime.clone();
	let res = thread::spawn(move || {
		r.block_on(async move {
			let res = c.bootstrap().await;
			if res.is_ok() {
				let mut percent = 0.0;
				let mut prev_percent = 0.0;
				while percent < 1.0 {
					percent = c.bootstrap_status().as_frac();
					if percent != prev_percent {
						info!("Starting Tor {}%", percent * 100.0);
					}
					prev_percent = percent;
					tokio::time::sleep(Duration::from_millis(1000)).await;
				}
			}
			res
		})
	})
	.join()
	.unwrap();
	match res {
		Ok(_) => info!("Tor client bootstrapped successfully"),
		Err(e) => return Err(Error::TorProcess(format!("{:?}", e))),
	}
	Ok((client, config))
}

/// Launch Onion service proxy.
async fn run_service_proxy<S>(
	client: TorClient<TokioNativeTlsRuntime>,
	addr: SocketAddr,
	request: S,
	nickname: HsNickname,
) -> Result<(), Error>
where
	S: futures::Stream<Item = tor_hsservice::RendRequest> + Unpin + Send + 'static,
{
	let runtime = client.runtime().clone();

	// Setup proxy to forward request from Tor address to local address.
	let proxy_rule = ProxyRule::new(
		ProxyPattern::one_port(80).unwrap(),
		ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(addr)),
	);
	let mut proxy_cfg_builder = ProxyConfigBuilder::default();
	proxy_cfg_builder.set_proxy_ports(vec![proxy_rule]);
	let proxy = OnionServiceReverseProxy::new(proxy_cfg_builder.build().unwrap());

	// Start proxy for launched service.
	proxy
		.handle_requests(runtime, nickname, request)
		.await
		.map_err(|e| Error::TorProcess(format!("{:?}", e)))
}

/// Save Onion service key to keystore.
fn add_service_key(
	mistrust: &Mistrust,
	key: &SecretKey,
	hs_nickname: &HsNickname,
	path: PathBuf,
) -> tor_keymgr::Result<()> {
	let arti_store = ArtiNativeKeystore::from_path_and_mistrust(path, mistrust)?;

	let key_manager = KeyMgrBuilder::default()
		.primary_store(Box::new(arti_store))
		.build()
		.unwrap();

	let expanded_sk =
		ExpandedSecretKey::from_bytes(Sha512::default().chain_update(key).finalize().as_ref());

	let mut sk_bytes = [0_u8; 64];
	sk_bytes[0..32].copy_from_slice(&expanded_sk.scalar.to_bytes());
	sk_bytes[32..64].copy_from_slice(&expanded_sk.hash_prefix);
	let expanded_kp = ExpandedKeypair::from_secret_key_bytes(sk_bytes).unwrap();

	key_manager.insert(
		HsIdKey::from(expanded_kp.public().clone()),
		&HsIdPublicKeySpecifier::new(hs_nickname.clone()),
		KeystoreSelector::Primary,
		true,
	)?;

	key_manager.insert(
		HsIdKeypair::from(expanded_kp),
		&HsIdKeypairSpecifier::new(hs_nickname.clone()),
		KeystoreSelector::Primary,
		true,
	)?;
	Ok(())
}
