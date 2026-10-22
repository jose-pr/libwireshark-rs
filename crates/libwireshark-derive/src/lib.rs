//! Derive macros for `libwireshark`. Use them through its `derive` feature,
//! which re-exports them from its root; this crate is not named directly.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as Tokens};
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, LitInt, LitStr, parse_macro_input};

/// Registered fields from a struct of integers, and `Self::decode` reading
/// them from packet bytes. Documented on `libwireshark::Header`.
#[proc_macro_derive(Header, attributes(header))]
pub fn derive_header(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    runtime_path(&input)
        .and_then(|runtime| expand_header(input, runtime))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Registered preferences from a struct of preference values. Documented on
/// `libwireshark::Preferences`.
#[proc_macro_derive(Preferences, attributes(preference))]
pub fn derive_preferences(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    runtime_path(&input)
        .and_then(|runtime| expand_preferences(input, runtime))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The path of the `libwireshark` crate as the deriving crate names it.
fn runtime_path(input: &DeriveInput) -> syn::Result<Tokens> {
    match crate_name("libwireshark") {
        // `libwireshark` declares `extern crate self as libwireshark`, so the
        // absolute path works in the crate, its tests and its doctests alike.
        Ok(FoundCrate::Itself) => Ok(quote!(::libwireshark)),
        Ok(FoundCrate::Name(name)) => {
            let name = format_ident!("{}", name);
            Ok(quote!(::#name))
        }
        Err(_) => Err(syn::Error::new_spanned(
            &input.ident,
            "this derive needs `libwireshark` as a direct dependency",
        )),
    }
}

fn named_fields(input: &DeriveInput, derive: &str) -> syn::Result<Vec<syn::Field>> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(fields.named.iter().cloned().collect()),
            _ => Err(syn::Error::new_spanned(
                &input.ident,
                format!("{derive} needs a struct with named fields"),
            )),
        },
        _ => Err(syn::Error::new_spanned(
            &input.ident,
            format!("{derive} can only be derived for a struct"),
        )),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Endian {
    Big,
    Little,
}

fn parse_endian(value: &LitStr) -> syn::Result<Endian> {
    match value.value().as_str() {
        "big" => Ok(Endian::Big),
        "little" => Ok(Endian::Little),
        _ => Err(syn::Error::new_spanned(
            value,
            "endian is \"big\" or \"little\"",
        )),
    }
}

/// An integer field's Rust type: its `FieldType` variant, width, signedness.
fn integer_type(ty: &syn::Type) -> Option<(&'static str, usize, bool)> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let ident = path.path.get_ident()?.to_string();
    Some(match ident.as_str() {
        "u8" => ("U8", 1, false),
        "u16" => ("U16", 2, false),
        "u32" => ("U32", 4, false),
        "u64" => ("U64", 8, false),
        "i8" => ("I8", 1, true),
        "i16" => ("I16", 2, true),
        "i32" => ("I32", 4, true),
        "i64" => ("I64", 8, true),
        _ => return None,
    })
}

fn expand_header(input: DeriveInput, runtime: Tokens) -> syn::Result<Tokens> {
    let fields = named_fields(&input, "Header")?;
    let mut struct_endian = Endian::Big;
    for attribute in input.attrs.iter().filter(|a| a.path().is_ident("header")) {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("endian") {
                struct_endian = parse_endian(&meta.value()?.parse()?)?;
                Ok(())
            } else {
                Err(meta.error("on the struct, header takes only `endian`"))
            }
        })?;
    }

    let mut infos = Vec::new();
    let mut inserts = Vec::new();
    let mut decoders = Vec::new();
    let mut next_offset = 0usize;
    let mut size = 0usize;
    for field in &fields {
        let ident = field.ident.clone().expect("named fields have identifiers");
        let mut abbrev = ident.to_string();
        let mut name = ident.to_string();
        let mut blurb = String::new();
        let mut base = quote!(Dec);
        let mut bitmask = 0u64;
        let mut offset = None;
        let mut endian = struct_endian;
        for attribute in field.attrs.iter().filter(|a| a.path().is_ident("header")) {
            attribute.parse_nested_meta(|meta| {
                let key = meta.path.get_ident().map(ToString::to_string).unwrap_or_default();
                match key.as_str() {
                    "abbrev" => abbrev = meta.value()?.parse::<LitStr>()?.value(),
                    "name" => name = meta.value()?.parse::<LitStr>()?.value(),
                    "blurb" => blurb = meta.value()?.parse::<LitStr>()?.value(),
                    "display" => {
                        let value = meta.value()?.parse::<LitStr>()?;
                        base = match value.value().as_str() {
                            "dec" => quote!(Dec),
                            "hex" => quote!(Hex),
                            "oct" => quote!(Oct),
                            "dec_hex" => quote!(DecHex),
                            "hex_dec" => quote!(HexDec),
                            _ => {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "display is \"dec\", \"hex\", \"oct\", \"dec_hex\" or \"hex_dec\"",
                                ));
                            }
                        };
                    }
                    "bitmask" => bitmask = meta.value()?.parse::<LitInt>()?.base10_parse()?,
                    "offset" => offset = Some(meta.value()?.parse::<LitInt>()?.base10_parse()?),
                    "endian" => endian = parse_endian(&meta.value()?.parse()?)?,
                    _ => {
                        return Err(meta.error(
                            "header takes abbrev, name, blurb, display, bitmask, offset or endian",
                        ));
                    }
                }
                Ok(())
            })?;
        }
        let (kind, width, signed) = integer_type(&field.ty).ok_or_else(|| {
            syn::Error::new_spanned(
                &field.ty,
                "Header fields are u8, u16, u32, u64, i8, i16, i32 or i64",
            )
        })?;
        let offset: usize = offset.unwrap_or(next_offset);
        next_offset = offset + width;
        size = size.max(next_offset);

        let kind = format_ident!("{kind}");
        let blurb = LitStr::new(&blurb, Span::call_site());
        let abbrev = LitStr::new(&abbrev, ident.span());
        let name = LitStr::new(&name, ident.span());
        infos.push(quote! {
            #runtime::FieldInfo::new(#name, #abbrev, #runtime::FieldType::#kind)
                .with_base(#runtime::Base::#base)
                .with_bitmask(#bitmask)
                .with_blurb(#blurb)
        });
        inserts.push(match (width, signed) {
            (8, false) => quote!(packet.add_uint64(#abbrev, #offset, self.#ident)?;),
            (8, true) => quote!(packet.add_int64(#abbrev, #offset, self.#ident)?;),
            (_, false) => quote!(packet.add_uint(#abbrev, #offset, ::core::convert::From::from(self.#ident))?;),
            (_, true) => quote!(packet.add_int(#abbrev, #offset, ::core::convert::From::from(self.#ident))?;),
        });
        let ty = &field.ty;
        let from_bytes = match endian {
            Endian::Big => quote!(from_be_bytes),
            Endian::Little => quote!(from_le_bytes),
        };
        let end = offset + width;
        decoders.push(quote! {
            #ident: <#ty>::#from_bytes(
                ::core::convert::TryInto::try_into(bytes.get(#offset..#end)?).ok()?
            ),
        });
    }

    let name = &input.ident;
    let vis = &input.vis;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics #runtime::Header for #name #type_generics #where_clause {
            fn fields() -> &'static [#runtime::FieldInfo] {
                const FIELDS: &[#runtime::FieldInfo] = &[#(#infos),*];
                FIELDS
            }

            fn add_to(
                &self,
                packet: &mut #runtime::PacketView<'_>,
            ) -> ::core::result::Result<(), #runtime::PacketFieldError> {
                #(#inserts)*
                ::core::result::Result::Ok(())
            }
        }

        impl #impl_generics #name #type_generics #where_clause {
            /// The header's length in bytes.
            #vis const SIZE: usize = #size;

            /// Reads the header from the start of `bytes`, or `None` when
            /// `bytes` is shorter than [`Self::SIZE`].
            #vis fn decode(bytes: &[u8]) -> ::core::option::Option<Self> {
                ::core::option::Option::Some(Self { #(#decoders)* })
            }
        }
    })
}

fn expand_preferences(input: DeriveInput, runtime: Tokens) -> syn::Result<Tokens> {
    let fields = named_fields(&input, "Preferences")?;
    let mut declarations = Vec::new();
    let mut readers = Vec::new();
    let mut generics = input.generics.clone();
    for field in &fields {
        let ident = field.ident.clone().expect("named fields have identifiers");
        let mut key = ident.to_string();
        let mut title = None;
        let mut description = String::new();
        let mut base = None::<u32>;
        for attribute in field
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("preference"))
        {
            attribute.parse_nested_meta(|meta| {
                let name = meta
                    .path
                    .get_ident()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                match name.as_str() {
                    "name" => key = meta.value()?.parse::<LitStr>()?.value(),
                    "title" => title = Some(meta.value()?.parse::<LitStr>()?.value()),
                    "description" => description = meta.value()?.parse::<LitStr>()?.value(),
                    "base" => {
                        let value = meta.value()?.parse::<LitInt>()?;
                        let parsed = value.base10_parse()?;
                        if ![8, 10, 16].contains(&parsed) {
                            return Err(syn::Error::new_spanned(value, "base is 8, 10 or 16"));
                        }
                        base = Some(parsed);
                    }
                    _ => {
                        return Err(meta.error("preference takes name, title, description or base"));
                    }
                }
                Ok(())
            })?;
        }
        let title = LitStr::new(&title.unwrap_or_else(|| key.clone()), ident.span());
        let key = LitStr::new(&key, ident.span());
        let description = LitStr::new(&description, ident.span());
        let ty = &field.ty;
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(#ty: #runtime::prefs::PreferenceValue));
        let base = base.map(|base| quote!(.with_base(#base)));
        declarations.push(quote! {
            #runtime::prefs::Declaration::new(
                #key,
                #title,
                #description,
                #runtime::prefs::PreferenceValue::to_value(&defaults.#ident),
            )#base
        });
        readers.push(quote! {
            if let ::core::option::Option::Some(value) = values.get(#key) {
                preferences.#ident =
                    <#ty as #runtime::prefs::PreferenceValue>::from_value(value)?;
            }
        });
    }

    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics #runtime::Preferences for #name #type_generics #where_clause {
            fn declarations() -> #runtime::__private::Vec<#runtime::prefs::Declaration> {
                let defaults = <Self as ::core::default::Default>::default();
                #runtime::__private::Vec::from([#(#declarations),*])
            }

            fn from_values(
                values: &#runtime::prefs::PreferenceMap,
            ) -> ::core::result::Result<Self, #runtime::prefs::PreferenceError> {
                let mut preferences = <Self as ::core::default::Default>::default();
                #(#readers)*
                ::core::result::Result::Ok(preferences)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{expand_header, expand_preferences};
    use quote::quote;
    use syn::parse_quote;

    fn compiles_as_items(tokens: proc_macro2::TokenStream) -> String {
        let source = tokens.to_string();
        syn::parse2::<syn::File>(tokens).expect("the expansion is valid Rust");
        source
    }

    #[test]
    fn a_header_lays_fields_out_one_after_another() {
        let input = parse_quote! {
            struct Foo {
                #[header(name = "Version", display = "hex")]
                version: u8,
                length: u16,
                #[header(offset = 8, endian = "little")]
                id: u32,
            }
        };
        let source = compiles_as_items(expand_header(input, quote!(::libwireshark)).unwrap());
        assert!(source.contains("const SIZE : usize = 12usize"));
        assert!(source.contains("bytes . get (1usize .. 3usize)"));
        assert!(source.contains("u32 > :: from_le_bytes"));
        assert!(source.contains("Base :: Hex"));
        assert!(
            source.contains("\"length\""),
            "the field name is the default abbreviation"
        );
    }

    #[test]
    fn a_header_refuses_a_non_integer_field() {
        let input = parse_quote! { struct Foo { name: String } };
        let error = expand_header(input, quote!(::libwireshark)).unwrap_err();
        assert!(error.to_string().contains("u8, u16"));
    }

    #[test]
    fn a_header_refuses_an_unknown_key() {
        let input = parse_quote! { struct Foo { #[header(size = 2)] a: u8 } };
        assert!(expand_header(input, quote!(::libwireshark)).is_err());
    }

    #[test]
    fn preferences_carry_their_key_title_and_base() {
        let input = parse_quote! {
            struct Settings {
                #[preference(name = "listen_port", title = "Listen port", base = 16)]
                port: u16,
                enabled: bool,
            }
        };
        let source = compiles_as_items(expand_preferences(input, quote!(::libwireshark)).unwrap());
        assert!(source.contains("\"listen_port\""));
        assert!(source.contains("with_base (16u32)"));
        assert!(
            source.contains("\"enabled\" , \"enabled\""),
            "the key is the default title"
        );
    }

    #[test]
    fn preferences_refuse_an_unsupported_base() {
        let input = parse_quote! { struct S { #[preference(base = 2)] port: u16 } };
        assert!(expand_preferences(input, quote!(::libwireshark)).is_err());
    }

    #[test]
    fn preferences_need_named_fields() {
        let input = parse_quote! { struct S(u32); };
        assert!(expand_preferences(input, quote!(::libwireshark)).is_err());
    }
}
