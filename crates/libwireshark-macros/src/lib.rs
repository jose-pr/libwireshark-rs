use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr, parse_macro_input, parse_quote};

/// Derives typed Wireshark preference declarations for a named-field struct.
///
/// Fields support `bool`, `u32`, and `String`; the field name is the default
/// preference key and title. `#[preference(name = "...", title = "...", description = "...")]`
/// overrides the corresponding metadata.
#[proc_macro_derive(Preferences, attributes(preference))]
pub fn derive_preferences(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let runtime = match runtime_path(&input.ident) {
        Ok(runtime) => runtime,
        Err(error) => return error.to_compile_error().into(),
    };
    match expand_preferences(input, runtime) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// Derives Wireshark registration metadata and packet-tree insertion from a header struct.
///
/// Each field requires `#[header(abbrev = "filter.name")]`; `name`, `blurb`,
/// `display` (`dec`, `hex`, or `oct`), `bitmask`, and byte `offset` are optional.
/// Without an offset, integer fields are laid out consecutively from byte zero.
#[proc_macro_derive(Header, attributes(header))]
pub fn derive_header(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let runtime = match runtime_path(&input.ident) {
        Ok(runtime) => runtime,
        Err(error) => return error.to_compile_error().into(),
    };
    match expand_header(input, runtime) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn expand_header(
    input: DeriveInput,
    runtime: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    let span = input.ident.span();
    let name = input.ident;
    let fields = match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    syn::Ident::new("struct", span),
                    "Header requires named struct fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                syn::Ident::new("struct", span),
                "Header can only be derived for a struct",
            ));
        }
    };
    let mut emitted = Vec::new();
    let mut add_fields = Vec::new();
    let mut next_offset = 0usize;
    for field in fields {
        let ident = field.ident.expect("named fields have identifiers");
        let default_name = ident.to_string();
        let mut field_name = default_name.clone();
        let mut abbreviation = None;
        let mut blurb = String::new();
        let mut display = "dec".to_owned();
        let mut bitmask = 0u64;
        let mut offset = None;
        for attribute in field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("header"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("abbrev") {
                    abbreviation = Some(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.path.is_ident("name") {
                    field_name = meta.value()?.parse::<LitStr>()?.value();
                } else if meta.path.is_ident("blurb") {
                    blurb = meta.value()?.parse::<LitStr>()?.value();
                } else if meta.path.is_ident("display") {
                    display = meta.value()?.parse::<LitStr>()?.value();
                } else if meta.path.is_ident("bitmask") {
                    bitmask = meta.value()?.parse::<syn::LitInt>()?.base10_parse()?;
                } else if meta.path.is_ident("offset") {
                    offset = Some(
                        meta.value()?
                            .parse::<syn::LitInt>()?
                            .base10_parse::<usize>()?,
                    );
                } else {
                    return Err(
                        meta.error("expected abbrev, name, blurb, display, bitmask, or offset")
                    );
                }
                Ok(())
            })?;
        }
        let abbrev = abbreviation.ok_or_else(|| {
            syn::Error::new_spanned(
                &ident,
                "header fields require #[header(abbrev = \"...\")] metadata",
            )
        })?;
        let abbrev = LitStr::new(&abbrev, ident.span());
        let field_offset = offset.unwrap_or(next_offset);
        let type_name = match &field.ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        }
        .ok_or_else(|| {
            syn::Error::new_spanned(&field.ty, "header field type must be a supported integer")
        })?;
        let (field_type, width, operation) = match type_name.as_str() {
            "u8" => (
                quote!(#runtime::bindings::ftenum_FT_UINT8),
                1usize,
                quote!(packet.add_uint(#abbrev, #field_offset, 1, self.#ident as u32)?;),
            ),
            "u16" => (
                quote!(#runtime::bindings::ftenum_FT_UINT16),
                2usize,
                quote!(packet.add_uint(#abbrev, #field_offset, 2, self.#ident as u32)?;),
            ),
            "u32" => (
                quote!(#runtime::bindings::ftenum_FT_UINT32),
                4usize,
                quote!(packet.add_uint(#abbrev, #field_offset, 4, self.#ident)?;),
            ),
            "u64" => (
                quote!(#runtime::bindings::ftenum_FT_UINT64),
                8usize,
                quote!(packet.add_uint64(#abbrev, #field_offset, self.#ident)?;),
            ),
            "i8" => (
                quote!(#runtime::bindings::ftenum_FT_INT8),
                1usize,
                quote!(packet.add_int(#abbrev, #field_offset, 1, self.#ident as i32)?;),
            ),
            "i16" => (
                quote!(#runtime::bindings::ftenum_FT_INT16),
                2usize,
                quote!(packet.add_int(#abbrev, #field_offset, 2, self.#ident as i32)?;),
            ),
            "i32" => (
                quote!(#runtime::bindings::ftenum_FT_INT32),
                4usize,
                quote!(packet.add_int(#abbrev, #field_offset, 4, self.#ident)?;),
            ),
            "i64" => (
                quote!(#runtime::bindings::ftenum_FT_INT64),
                8usize,
                quote!(packet.add_int64(#abbrev, #field_offset, self.#ident)?;),
            ),
            _ => {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    "Header supports u8/u16/u32/u64 and i8/i16/i32/i64 fields",
                ));
            }
        };
        let display = match display.as_str() {
            "dec" => quote!(#runtime::bindings::field_display_e_BASE_DEC),
            "hex" => quote!(#runtime::bindings::field_display_e_BASE_HEX),
            "oct" => quote!(#runtime::bindings::field_display_e_BASE_OCT),
            _ => {
                return Err(syn::Error::new_spanned(
                    &ident,
                    "display must be dec, hex, or oct",
                ));
            }
        };
        let field_name = LitStr::new(&field_name, ident.span());
        let blurb = LitStr::new(&blurb, ident.span());
        next_offset = field_offset.saturating_add(width);
        emitted.push(quote! {
            #runtime::header::HeaderFieldInfo {
                name: #field_name,
                abbrev: #abbrev,
                type_: #field_type,
                display: #display,
                bitmask: #bitmask,
                blurb: #blurb,
            }
        });
        add_fields.push(operation);
    }
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics #runtime::header::Header for #name #type_generics #where_clause {
            fn fields() -> &'static [#runtime::header::HeaderFieldInfo] {
                &[#(#emitted),*]
            }

            fn add_to(
                &self,
                packet: &mut #runtime::dissector::PacketView<'_>,
            ) -> ::core::result::Result<(), #runtime::dissector::PacketFieldError> {
                #(#add_fields)*
                ::core::result::Result::Ok(())
            }
        }
    })
}

fn runtime_path(span: &impl quote::ToTokens) -> syn::Result<proc_macro2::TokenStream> {
    let runtime = match crate_name("libwireshark") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let name = quote::format_ident!("{}", name);
            quote!(::#name)
        }
        Err(_) => {
            return Err(syn::Error::new_spanned(
                span,
                "Preferences derive requires libwireshark as a direct dependency",
            ));
        }
    };
    Ok(runtime)
}

fn expand_preferences(
    input: DeriveInput,
    runtime: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    let span = input.ident.span();
    let name = input.ident;
    let mut generics = input.generics;
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(Self: ::core::default::Default));
    let fields = match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    syn::Ident::new("struct", span),
                    "Preferences requires named struct fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                syn::Ident::new("struct", span),
                "Preferences can only be derived for a struct",
            ));
        }
    };

    let mut descriptors = Vec::new();
    let mut readers = Vec::new();
    for field in fields {
        let ident = field.ident.expect("named fields have identifiers");
        let key = ident.to_string();
        let mut title = key.clone();
        let mut description = String::new();
        let mut name_override = None;
        for attribute in field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("preference"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    name_override = Some(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.path.is_ident("title") {
                    title = meta.value()?.parse::<LitStr>()?.value();
                } else if meta.path.is_ident("description") {
                    description = meta.value()?.parse::<LitStr>()?.value();
                } else {
                    return Err(meta.error("expected name, title, or description"));
                }
                Ok(())
            })?;
        }
        let key = name_override.unwrap_or(key);
        let key = LitStr::new(&key, ident.span());
        let title = LitStr::new(&title, ident.span());
        let description = LitStr::new(&description, ident.span());
        let ty = field.ty;
        generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(#ty: #runtime::prefs::PreferenceValue));
        descriptors.push(quote! {
            #runtime::prefs::ModulePref {
                value_type: #runtime::prefs::PreferenceValue::to_pref_value(&defaults.#ident),
                name: #key,
                title: #title,
                description: #description,
            }
        });
        readers.push(quote! {
            if let Some(value) = values.get(#key) {
                result.#ident = <#ty as #runtime::prefs::PreferenceValue>::from_pref_value(value)?;
            }
        });
    }

    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics #runtime::prefs::Preferences for #name #type_generics #where_clause {
            fn module_preferences() -> ::std::vec::Vec<#runtime::prefs::ModulePref> {
                let defaults = Self::default();
                ::std::vec![#(#descriptors),*]
            }

            fn from_values(
                values: &#runtime::prefs::PreferenceMap,
            ) -> ::core::result::Result<Self, #runtime::prefs::PreferenceError> {
                let mut result = Self::default();
                #(#readers)*
                ::core::result::Result::Ok(result)
            }
        }
    })
}

/// Exports Wireshark plugin metadata and a `plugin_register` entry point.
///
/// Apply this attribute to a type implementing `WiresharkPlugin`. Its
/// `protocols()` method can register multiple protocol implementations. A
/// synchronous function returning `Protocol` remains supported for simple
/// single-protocol plugins. The runtime crate may be renamed in `Cargo.toml`.
#[proc_macro_attribute]
pub fn wireshark_plugin(attributes: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as syn::Item);
    if !attributes.is_empty() {
        return syn::Error::new_spanned(&item, "wireshark_plugin does not accept arguments")
            .to_compile_error()
            .into();
    }

    let runtime = match crate_name("libwireshark") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let name = quote::format_ident!("{}", name);
            quote!(::#name)
        }
        Err(_) => {
            return syn::Error::new_spanned(
                &item,
                "wireshark_plugin requires libwireshark as a direct dependency",
            )
            .to_compile_error()
            .into();
        }
    };

    match item {
        syn::Item::Fn(function) => {
            if function.sig.asyncness.is_some()
                || !function.sig.generics.params.is_empty()
                || !function.sig.inputs.is_empty()
                || function.sig.unsafety.is_some()
                || function.sig.variadic.is_some()
                || function.sig.abi.is_some()
            {
                return syn::Error::new_spanned(
                    &function.sig,
                    "wireshark_plugin requires a synchronous Rust function with no arguments or generics",
                )
                .to_compile_error()
                .into();
            }
            let name = &function.sig.ident;
            let exports = plugin_exports(
                runtime.clone(),
                quote!(#runtime::__initialize_protocol(#name())),
                quote!(env!("CARGO_PKG_VERSION")),
            );
            quote!(#function #exports).into()
        }
        syn::Item::Struct(plugin) => {
            if !plugin.generics.params.is_empty() {
                return syn::Error::new_spanned(
                    &plugin.generics,
                    "wireshark_plugin does not support generic plugin types",
                )
                .to_compile_error()
                .into();
            }
            let name = &plugin.ident;
            let exports = plugin_exports(
                runtime.clone(),
                quote!(#runtime::__initialize_plugin::<#name>()),
                quote!({
                    match <#name as #runtime::WiresharkPlugin>::OPTIONS.version {
                        Some(version) => version,
                        None => env!("CARGO_PKG_VERSION"),
                    }
                }),
            );
            quote!(#plugin #exports).into()
        }
        item => syn::Error::new_spanned(
            item,
            "wireshark_plugin must be applied to a WiresharkPlugin type or a protocol function",
        )
        .to_compile_error()
        .into(),
    }
}

fn plugin_exports(
    runtime: proc_macro2::TokenStream,
    initialize: proc_macro2::TokenStream,
    version: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        const __LIBWIRESHARK_PLUGIN_VERSION: &str = #version;

        #[unsafe(no_mangle)]
        #[used]
        pub static plugin_version: [u8; __LIBWIRESHARK_PLUGIN_VERSION.len() + 1] = {
            let source = __LIBWIRESHARK_PLUGIN_VERSION.as_bytes();
            let mut bytes = [0u8; __LIBWIRESHARK_PLUGIN_VERSION.len() + 1];
            let mut index = 0;
            while index < source.len() {
                bytes[index] = source[index];
                index += 1;
            }
            bytes
        };

        #[unsafe(no_mangle)]
        #[used]
        pub static plugin_want_major: i32 = #runtime::bindings::VERSION_MAJOR as i32;

        #[unsafe(no_mangle)]
        #[used]
        pub static plugin_want_minor: i32 = #runtime::bindings::VERSION_MINOR as i32;

        #[unsafe(no_mangle)]
        pub extern "C" fn plugin_register() {
            let _ = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                if #initialize {
                    // SAFETY: This generated entry point runs only when Wireshark loads this plugin.
                    unsafe { #runtime::plugin_register() }
                }
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{expand_header, expand_preferences, plugin_exports};
    use quote::quote;
    use syn::parse_quote;

    #[test]
    fn derives_named_preference_fields_and_custom_metadata() {
        let input = parse_quote! {
            struct Settings {
                #[preference(name = "listen-port", title = "Listen port", description = "UDP port")]
                port: u32,
                enabled: bool,
                token: String,
            }
        };
        let generated = expand_preferences(input, quote!(::libwireshark))
            .unwrap()
            .to_string();
        assert!(generated.contains("impl :: libwireshark :: prefs :: Preferences for Settings"));
        assert!(generated.contains("listen-port"));
        assert!(generated.contains("UDP port"));
        assert!(generated.contains("from_pref_value"));
    }

    #[test]
    fn rejects_unnamed_preference_fields() {
        let input = parse_quote! { struct Settings(u32); };
        let error = expand_preferences(input, quote!(::libwireshark))
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires named struct fields"));
    }

    #[test]
    fn derives_registered_header_fields_from_integer_types() {
        let input = parse_quote! {
            struct PacketHeader {
                #[header(abbrev = "demo.kind", name = "Kind", display = "hex", bitmask = 0x0f)]
                kind: u8,
                #[header(abbrev = "demo.length")]
                length: u16,
            }
        };
        let generated = expand_header(input, quote!(::libwireshark))
            .unwrap()
            .to_string();
        assert!(generated.contains("impl :: libwireshark :: header :: Header for PacketHeader"));
        assert!(generated.contains("ftenum_FT_UINT8"));
        assert!(generated.contains("ftenum_FT_UINT16"));
        assert!(generated.contains("BASE_HEX"));
        assert!(generated.contains("demo.kind"));
        assert!(generated.contains("fn add_to"));
        assert!(generated.contains("packet . add_uint"));
        assert!(generated.contains("self . kind"));
    }

    #[test]
    fn plugin_exports_can_use_a_dissector_type() {
        let generated = plugin_exports(
            quote!(::libwireshark),
            quote!(::libwireshark::__initialize_plugin::<FooPlugin>()),
            quote!(env!("CARGO_PKG_VERSION")),
        );
        let generated_source = generated.to_string();
        assert!(generated_source.contains("plugin_register"));
        assert!(generated_source.contains("plugin_version"));
        assert!(generated_source.contains("__initialize_plugin :: < FooPlugin >"));
        assert!(generated_source.contains("plugin_want_major : i32"));
        syn::parse2::<syn::File>(generated)
            .expect("generated plugin exports are valid Rust syntax");
    }
}
