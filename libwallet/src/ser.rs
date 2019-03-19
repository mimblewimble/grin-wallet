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

//! Wallet Type serialisation, mostly in place to ensure u64s are serialised
//! as strings by default, but can be read as either
//! From solutions on:
//! https://github.com/serde-rs/json/issues/329


pub mod string_or_u64 {
	use std::fmt;

	use serde::{de, Deserializer, Serializer};

	pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		serializer.collect_str(value)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Visitor;
		impl<'a> de::Visitor<'a> for Visitor {
			type Value = u64;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				write!(
					formatter,
					"a string containing digits or an int fitting into u64"
				)
			}
			fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
				Ok(v)
			}
			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				s.parse().map_err(de::Error::custom)
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}

#[allow(unused)]
mod string_or_i64 {
	use std::fmt;

	use serde::{de, Deserializer, Serializer};

	pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		serializer.collect_str(value)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Visitor;
		impl<'a> de::Visitor<'a> for Visitor {
			type Value = i64;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				write!(
					formatter,
					"a string containing digits or an int fitting into i64"
				)
			}
			fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
				Ok(v)
			}
			fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				if (v as i64) < 0 {
					Err(de::Error::invalid_value(de::Unexpected::Unsigned(v), &self))
				} else {
					Ok(v as i64)
				}
			}
			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				s.parse().map_err(de::Error::custom)
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}
