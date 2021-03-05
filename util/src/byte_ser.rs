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

//! Simple serde byte array serializer, assumes target already
//! knows how to serialize itself into binary (because that all
//! this serializer can do)

use serde::de::Visitor;
use serde::{de, ser, Deserialize, Serialize};
use std;
use std::fmt::{self, Display};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
	Message(String),
}

impl ser::Error for Error {
	fn custom<T: Display>(msg: T) -> Self {
		Error::Message(msg.to_string())
	}
}

impl de::Error for Error {
	fn custom<T: Display>(msg: T) -> Self {
		Error::Message(msg.to_string())
	}
}

impl Display for Error {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::Message(msg) => formatter.write_str(msg),
		}
	}
}

impl std::error::Error for Error {}

pub struct ByteSerializer {
	output: Vec<u8>,
}

pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>>
where
	T: Serialize,
{
	let mut serializer = ByteSerializer { output: vec![] };
	value.serialize(&mut serializer)?;
	Ok(serializer.output)
}

impl<'a> ser::Serializer for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;
	type SerializeSeq = Self;
	type SerializeTuple = Self;
	type SerializeTupleStruct = Self;
	type SerializeTupleVariant = Self;
	type SerializeMap = Self;
	type SerializeStruct = Self;
	type SerializeStructVariant = Self;

	fn serialize_bool(self, _: bool) -> Result<()> {
		unimplemented!()
	}

	fn serialize_i8(self, _: i8) -> Result<()> {
		unimplemented!()
	}

	fn serialize_i16(self, _: i16) -> Result<()> {
		unimplemented!()
	}

	fn serialize_i32(self, _: i32) -> Result<()> {
		unimplemented!()
	}

	fn serialize_i64(self, _: i64) -> Result<()> {
		unimplemented!()
	}

	fn serialize_u8(self, _: u8) -> Result<()> {
		unimplemented!()
	}

	fn serialize_u16(self, _: u16) -> Result<()> {
		unimplemented!()
	}

	fn serialize_u32(self, _: u32) -> Result<()> {
		unimplemented!()
	}

	fn serialize_u64(self, _: u64) -> Result<()> {
		unimplemented!()
	}

	fn serialize_f32(self, _: f32) -> Result<()> {
		unimplemented!()
	}

	fn serialize_f64(self, _: f64) -> Result<()> {
		unimplemented!()
	}

	fn serialize_char(self, _: char) -> Result<()> {
		unimplemented!()
	}

	fn serialize_str(self, _: &str) -> Result<()> {
		unimplemented!()
	}

	fn serialize_bytes(self, v: &[u8]) -> Result<()> {
		for byte in v {
			self.output.push(*byte)
		}
		Ok(())
	}

	fn serialize_none(self) -> Result<()> {
		unimplemented!()
	}

	fn serialize_some<T>(self, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn serialize_unit(self) -> Result<()> {
		unimplemented!()
	}

	fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
		unimplemented!()
	}

	fn serialize_unit_variant(
		self,
		_name: &'static str,
		_variant_index: u32,
		_variant: &'static str,
	) -> Result<()> {
		unimplemented!()
	}

	fn serialize_newtype_struct<T>(self, _name: &'static str, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn serialize_newtype_variant<T>(
		self,
		_name: &'static str,
		_variant_index: u32,
		_variant: &'static str,
		_value: &T,
	) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
		unimplemented!()
	}

	fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
		unimplemented!()
	}

	fn serialize_tuple_struct(
		self,
		_name: &'static str,
		_len: usize,
	) -> Result<Self::SerializeTupleStruct> {
		unimplemented!()
	}

	fn serialize_tuple_variant(
		self,
		_name: &'static str,
		_variant_index: u32,
		_variant: &'static str,
		_len: usize,
	) -> Result<Self::SerializeTupleVariant> {
		unimplemented!()
	}

	fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
		unimplemented!()
	}

	fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
		unimplemented!()
	}

	fn serialize_struct_variant(
		self,
		_name: &'static str,
		_variant_index: u32,
		_variant: &'static str,
		_len: usize,
	) -> Result<Self::SerializeStructVariant> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeSeq for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;

	fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> Result<()> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeTuple for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;

	fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> Result<()> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeTupleStruct for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;

	fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> Result<()> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeTupleVariant for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;

	fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> Result<()> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeMap for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;

	fn serialize_key<T>(&mut self, _key: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn serialize_value<T>(&mut self, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> Result<()> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeStruct for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;

	fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> Result<()> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeStructVariant for &'a mut ByteSerializer {
	type Ok = ();
	type Error = Error;

	fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> Result<()> {
		unimplemented!()
	}
}

// Simple Deserializer

pub struct ByteDeserializer<'de> {
	input: &'de [u8],
}

impl<'de> ByteDeserializer<'de> {
	pub fn from_bytes(input: &'de [u8]) -> Self {
		ByteDeserializer { input }
	}
}

pub fn from_bytes<'a, T>(b: &'a [u8]) -> Result<T>
where
	T: Deserialize<'a>,
{
	let mut deserializer = ByteDeserializer::from_bytes(b);
	let t = T::deserialize(&mut deserializer)?;
	Ok(t)
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut ByteDeserializer<'de> {
	type Error = Error;

	fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
	where
		V: Visitor<'de>,
	{
		visitor.visit_bytes(self.input)
	}

	serde::forward_to_deserialize_any! {
		bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
		bytes byte_buf option unit unit_struct newtype_struct seq tuple
		tuple_struct map struct enum identifier ignored_any
	}
}
