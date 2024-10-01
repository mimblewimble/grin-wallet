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

//! proc-macro crate to generate OpenAPI documentation for specified functions

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

mod openapi_fn;

use proc_macro::TokenStream;
use proc_macro2::{Group, Ident, Punct, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{
	bracketed,
	parse::{Parse, ParseStream},
	punctuated::Punctuated,
	token::Bracket,
	DeriveInput, ExprPath, GenericParam, ItemFn, Lit, LitStr, Member, Token,
};

use openapi_fn::{OpenAPIFn, OpenAPIFnAttr};

#[proc_macro_attribute]
pub fn derive_openapi_fn(input: TokenStream, item: TokenStream) -> TokenStream {
	let fn_attribute = syn::parse_macro_input!(input as OpenAPIFnAttr);
	let ast_fn = match syn::parse::<ItemFn>(item) {
		Ok(ast_fn) => ast_fn,
		Err(error) => return error.into_compile_error().into_token_stream().into(),
	};
	let path = OpenAPIFn::new(fn_attribute, &ast_fn.sig.ident)
		.doc_comments(CommentAttributes::from(&ast_fn.attrs).0);

	let handler = path::handler::Handler {
		path,
		handler_fn: &ast_fn,
	};

	handler.to_token_stream().into()
}
