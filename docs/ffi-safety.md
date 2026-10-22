# FFI safety contract

The `libwireshark-sys` crate is a raw binding layer. Its pointers and functions follow the C API and are `unsafe` to use correctly. The `libwireshark` packet callback accepts a callback-scoped `PacketView`; raw pointer conversion remains inside the callback trampoline.

## Ownership and lifetime

- Packet buffers, packet information, protocol trees, dissector handles, and preference storage have Wireshark-defined ownership. `PacketView<'packet>` borrows packet and callback context through the dissector callback and does not expose its raw pointers. Each registered protocol handle carries a pointer to a boxed protocol index retained by the plugin's process-lifetime state; the runtime uses that index to select the matching protocol callback and fields.
- A `PacketView` cannot be safely retained after the callback. It is neither `Send` nor `Sync`, and it does not own or release Wireshark's packet, packet-info, or tree storage.
- `captured_len` and `reported_len` expose the tvbuff lengths. Numeric reads cover signed and unsigned 8-, 16-, 24-, 32-, and 64-bit values; multi-byte reads specify big-endian or little-endian order. They return `None` unless the complete requested range is captured and representable by the native offset type.
- `add_uint`, `add_int`, `add_uint64`, and `add_int64` validate the registered field type, expected width, captured range, and representable value before calling EPAN. `add_item` checks that the field and tree exist and that its full byte range is captured, then delegates decoding to Wireshark with caller-supplied `ENC_*` flags.
- Tree insertion returns `PacketFieldError`: `NoTree`, `UnknownField`, `UnsupportedFieldType`, `WidthMismatch`, `OutOfBounds`, or `ValueOutOfRange`. Callers can match known cases while the non-exhaustive error permits future additions.
- `add_info` converts text to a C string and calls the Wireshark API that copies it during the call. It returns `NulError` for interior NUL bytes and is a no-op when packet-info or column data is unavailable.
- Values registered with Wireshark remain at stable addresses for the registration lifetime. Their backing storage is owned by a registration object retained for at least as long as Wireshark may access it.
- Memory allocated by Wireshark is released only by the matching Wireshark API. Rust allocations are released by Rust unless ownership is explicitly transferred.
- C strings are validated for interior NUL bytes and retained for the duration required by the registering API. User-provided invalid UTF-8 is handled explicitly; it is never silently converted with `unwrap()`.

## Callbacks and panics

Every Rust function callable from C must use the exact ABI signature. A Rust panic must never unwind through C. Callback trampolines catch unwinds at the FFI boundary; the dissector callback returns zero bytes after a panic, and void registration callbacks return. `panic=abort` remains process-fatal by Rust semantics. No callback may assume a pointer is non-null unless the C API contract guarantees it.

## Threading and global state

Wireshark registration callbacks are called during plugin initialization. The runtime initializes private registration state once and protects access with a mutex. Its private state wrapper has an unsafe `Send` implementation; callback code accesses it only while holding the mutex. Packet and tree pointers remain callback-scoped; callers must follow the threading requirements of the Wireshark APIs used inside a dissector.

## API layering

- `libwireshark-sys`: raw generated FFI and native link/discovery metadata.
- `libwireshark`: safe or explicitly unsafe wrapper methods with callback-scoped packet/tree access, registration ownership, and checked conversions.
- `libwireshark-macros`: optional code generation that only calls the public runtime API.

Any safe wrapper around raw pointers must uphold nullability, alignment, aliasing, lifetime, thread-safety, and ownership requirements for every input accepted by that safe API.
