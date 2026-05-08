// Copyright 2024 The Grin Developers
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

//! Definitions to generate OpenAPI documentation for specified functions

use proc_macro2::Ident;
use syn::{
	bracketed,
	parse::{Parse, ParseStream},
	LitStr,
};

#[derive(Default, Debug)]
pub struct OpenAPIFnAttr {}

impl OpenAPIFnAttr {
	pub fn new(params: String) -> Self {
		OpenAPIFnAttr {}
	}
}

pub struct OpenAPIFn<'p> {
	openapi_fn_attr: OpenAPIFnAttr,
	fn_ident: &'p Ident,
}

impl<'p> OpenAPIFn<'p> {
	pub fn new(openapi_fn_attr: OpenAPIFnAttr, fn_ident: &'p Ident) -> Self {
		OpenAPIFn {
			openapi_fn_attr,
			fn_ident,
		}
	}
}

impl Parse for OpenAPIFnAttr {
	fn parse(input: ParseStream) -> syn::Result<Self> {
		let content;
		let _ = bracketed!(content in input);
		let fn_attr = OpenAPIFnAttr::default();
		Ok(fn_attr)
	}
}
