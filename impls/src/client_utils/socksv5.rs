// MIT License
//
// Copyright (c) 2017 Vesa Vilhonen
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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

use byteorder::{BigEndian, WriteBytesExt};
use futures::future::ok;
use futures::{Future, IntoFuture};
//use hyper_tls::MaybeHttpsStream;
//use native_tls::TlsConnector;
use std::io::{self, Error, ErrorKind, Write};
use std::net::SocketAddr;
use tokio_io::io::{read_exact, write_all};
use tokio_tcp::TcpStream;
//use tokio_tls::TlsConnectorExt;
use hyper::client::connect::{Connect, Connected, Destination};

pub struct Socksv5Connector {
	proxy_addr: SocketAddr,
	creds: Option<(Vec<u8>, Vec<u8>)>,
}

impl Socksv5Connector {
	pub fn new(proxy_addr: SocketAddr) -> Socksv5Connector {
		Socksv5Connector {
			proxy_addr,
			creds: None,
		}
	}

	pub fn _new_with_creds<T: Into<Vec<u8>>>(
		proxy_addr: SocketAddr,
		creds: (T, T),
	) -> io::Result<Socksv5Connector> {
		let username = creds.0.into();
		let password = creds.1.into();
		if username.len() > 255 || password.len() > 255 {
			Err(Error::new(ErrorKind::Other, "invalid credentials"))
		} else {
			Ok(Socksv5Connector {
				proxy_addr,
				creds: Some((username, password)),
			})
		}
	}
}

impl Connect for Socksv5Connector {
	type Transport = TcpStream;
	type Error = Error;
	type Future = Box<dyn Future<Item = (Self::Transport, Connected), Error = Self::Error> + Send>;

	fn connect(&self, dst: Destination) -> Self::Future {
		let creds = self.creds.clone();
		Box::new(
			TcpStream::connect(&self.proxy_addr)
				.and_then(move |socket| do_handshake(socket, dst, creds)),
		)
	}
}

type HandshakeFutureConnected<T> = Box<dyn Future<Item = (T, Connected), Error = Error> + Send>;
type HandshakeFuture<T> = Box<dyn Future<Item = T, Error = Error> + Send>;

fn auth_negotiation(
	socket: TcpStream,
	creds: Option<(Vec<u8>, Vec<u8>)>,
) -> HandshakeFuture<TcpStream> {
	let (username, password) = creds.unwrap();
	let mut creds_msg: Vec<u8> = Vec::with_capacity(username.len() + password.len() + 3);
	creds_msg.push(1);
	creds_msg.push(username.len() as u8);
	creds_msg.extend_from_slice(&username);
	creds_msg.push(password.len() as u8);
	creds_msg.extend_from_slice(&password);
	Box::new(
		write_all(socket, creds_msg)
			.and_then(|(socket, _)| read_exact(socket, [0; 2]))
			.and_then(|(socket, resp)| {
				if resp[0] == 1 && resp[1] == 0 {
					Ok(socket)
				} else {
					Err(Error::new(ErrorKind::InvalidData, "unauthorized"))
				}
			}),
	)
}

fn answer_hello(
	socket: TcpStream,
	response: [u8; 2],
	creds: Option<(Vec<u8>, Vec<u8>)>,
) -> HandshakeFuture<TcpStream> {
	if response[0] == 5 && response[1] == 0 {
		Box::new(ok(socket))
	} else if response[0] == 5 && response[1] == 2 && creds.is_some() {
		Box::new(auth_negotiation(socket, creds).and_then(|socket| ok(socket)))
	} else {
		Box::new(
			Err(Error::new(
				ErrorKind::InvalidData,
				"wrong response from socks server",
			))
			.into_future(),
		)
	}
}

fn write_addr(socket: TcpStream, req: Destination) -> HandshakeFuture<TcpStream> {
	let host = req.host();
	if host.len() > u8::max_value() as usize {
		return Box::new(Err(Error::new(ErrorKind::InvalidInput, "Host too long")).into_future());
	}

	let port = match req.port() {
		Some(port) => port,
		_ if req.scheme() == "https" => 443,
		_ if req.scheme() == "http" => 80,
		_ => {
			return Box::new(
				Err(Error::new(
					ErrorKind::InvalidInput,
					"Supports only http/https",
				))
				.into_future(),
			)
		}
	};

	let mut packet = Vec::new();
	packet.write_all(&vec![5, 1, 0]).unwrap();

	packet.write_u8(3).unwrap();
	packet.write_u8(host.as_bytes().len() as u8).unwrap();
	packet.write_all(host.as_bytes()).unwrap();
	packet.write_u16::<BigEndian>(port).unwrap();

	Box::new(write_all(socket, packet).map(|(socket, _)| socket))
}

fn read_response(socket: TcpStream, response: [u8; 3]) -> HandshakeFuture<TcpStream> {
	if response[0] != 5 {
		return Box::new(Err(Error::new(ErrorKind::Other, "invalid version")).into_future());
	}
	match response[1] {
		0 => {}
		1 => {
			return Box::new(
				Err(Error::new(ErrorKind::Other, "general SOCKS server failure")).into_future(),
			)
		}
		2 => {
			return Box::new(
				Err(Error::new(
					ErrorKind::Other,
					"connection not allowed by ruleset",
				))
				.into_future(),
			)
		}
		3 => {
			return Box::new(Err(Error::new(ErrorKind::Other, "network unreachable")).into_future())
		}
		4 => return Box::new(Err(Error::new(ErrorKind::Other, "host unreachable")).into_future()),
		5 => {
			return Box::new(Err(Error::new(ErrorKind::Other, "connection refused")).into_future())
		}
		6 => return Box::new(Err(Error::new(ErrorKind::Other, "TTL expired")).into_future()),
		7 => {
			return Box::new(
				Err(Error::new(ErrorKind::Other, "command not supported")).into_future(),
			)
		}
		8 => {
			return Box::new(
				Err(Error::new(ErrorKind::Other, "address kind not supported")).into_future(),
			)
		}
		_ => return Box::new(Err(Error::new(ErrorKind::Other, "unknown error")).into_future()),
	};

	if response[2] != 0 {
		return Box::new(
			Err(Error::new(ErrorKind::InvalidData, "invalid reserved byt")).into_future(),
		);
	}

	Box::new(
		read_exact(socket, [0; 1])
			.and_then(|(socket, response)| match response[0] {
				1 => read_exact(socket, [0; 6]),
				_ => unimplemented!(),
			})
			.map(|(socket, _)| socket),
	)
}

fn do_handshake(
	socket: TcpStream,
	req: Destination,
	creds: Option<(Vec<u8>, Vec<u8>)>,
) -> HandshakeFutureConnected<TcpStream> {
	let _is_https = req.scheme() == "https";
	let _host = req.host();
	let method: u8 = creds.clone().map(|_| 2).unwrap_or(0);
	let established = write_all(socket, [5, 1, method])
		.and_then(|(socket, _)| read_exact(socket, [0; 2]))
		.and_then(|(socket, response)| answer_hello(socket, response, creds))
		.and_then(|socket| write_addr(socket, req))
		.and_then(|socket| read_exact(socket, [0; 3]))
		.and_then(|(socket, response)| read_response(socket, response));
	/*if is_https {
			Box::new(established.and_then(move |socket| {
					let tls = TlsConnector::builder().unwrap().build().unwrap();
					tls.connect_async(&host, socket)
							.map_err(|err| Error::new(ErrorKind::Other, err))
							.map(|socket| MaybeHttpsStream::Https(socket))
			}))
	} else {*/
	//Box::new(established.map(|socket| TcpStream::Http(socket)))
	Box::new(established.map(|socket| (socket, Connected::new())))
	/*}*/
}
