# `libwireshark-derive` — API header

Header-file-style reference for the `libwireshark-derive` crate: every public item with
its signature, contract and gotchas, so the crate can be used without
reading its source. It ships inside the package and is self-contained.
Development documentation lives with the source at
<https://github.com/jose-pr/libwireshark-rs>.

No features. MSRV 1.89. Depends on `syn`, `quote`, `proc-macro2` and
`proc-macro-crate`. No `unsafe`.

Use it through `libwireshark = { features = ["derive"] }`, which re-exports
both macros from `libwireshark`'s root; that crate's `AGENTS.md` documents
their attributes and generated items.

## Macros

```rust
#[proc_macro_derive(Header, attributes(header))]
#[proc_macro_derive(Preferences, attributes(preference))]
```

Expansions name `libwireshark` by the path the deriving crate gives it
(renamed dependencies work) and fail with "this derive needs `libwireshark`
as a direct dependency" when it has none.

## Errors

Compile errors, spanned at the offending item: a tuple struct, an enum, a
`Header` field that is not `u8 u16 u32 u64 i8 i16 i32 i64 bool [u8; N]
Ipv4Addr Ipv6Addr`, an unknown attribute key, a `display`/`endian`/`kind`
value outside its set, `kind = "ether"` on anything but `[u8; 6]`, `values`
on anything but an integer of up to 32 bits, a `base` other than 8, 10 or 16.
