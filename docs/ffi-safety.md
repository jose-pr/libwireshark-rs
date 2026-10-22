# FFI safety

`libwireshark-sys` is raw C: every function is `unsafe`. `libwireshark`
wraps both sides of the boundary, Wireshark calling the plugin and the
plugin calling Wireshark, so a plugin needs no `unsafe`. Its `unsafe`
is in `src/packet.rs`, `src/tap.rs`, `src/filter.rs`, `src/file_type.rs`
and the `src/plugin/` module; a test fails if any other file gains some.

## Wireshark calling the plugin

- Every `extern "C"` callback runs its body under `catch_unwind`: a panic
  declines the packet, or abandons the registration step, and never unwinds
  into C.
- The dissector callback's data is the protocol's boxed `Shared`, created
  before the handle and never freed.
- `PacketView<'packet>` borrows the callback's buffer, packet info and tree;
  it is neither `Send` nor `Sync` and cannot outlive the callback.

## The plugin calling Wireshark

- `PacketView::bytes` asks `tvb_get_ptr` for exactly the captured length,
  so the slice covers initialised memory owned by the buffer.
- Field insertion checks the field is registered, its type fits the
  operation, the value fits its width, and the byte range is captured,
  before calling EPAN.
- Column text is copied by Wireshark; interior NULs end it.
- `frame_data`'s flags are read where the compiler put them: bindgen lays
  bitfields out as GCC does, so on MSVC targets the flag unit is copied from
  its `unsigned int` boundary before the binding's accessor reads it.
- Display-filter symbols are looked up by name in the already loaded
  libwireshark and GLib, each with the signature its 4.4 header declares; a
  missing one disables the plugin's filter functions. A `FieldValue` is read
  only through the getter for its field type, and borrows the call.
- A filter function's results are new values appended to Wireshark's
  result cell, which owns and frees them; text is copied by
  `fvalue_set_string`, and display text from `fvalue_to_string_repr` is
  freed with `g_free`.
- A file reader writes only the fields of `struct wtap` up to
  `file_tsprec`, declared to match `wiretap/wtap_module.h`; later fields
  moved between 4.6 releases and are never touched. Packet data is written
  into the record's buffer after `ws_buffer_assure_space` reserves it, and
  the buffer's length moves only past bytes written. Error messages handed
  back are `g_strdup` copies, which Wireshark frees.
- A codec's output buffer is used only when it is aligned for `i16`, and
  only up to the length Wireshark gives.

## Memory Wireshark keeps

- Protocol names, field descriptors and their strings, and field-id slots
  are owned by the protocol's runtime, which lives for the process; their
  addresses do not move after registration.
- Preference slots and names are leaked deliberately: Wireshark writes the
  slots and keeps the names for the process. String preference values are
  allocated with GLib's `g_strdup` because Wireshark frees and replaces them
  with `g_free`; GLib is loaded at run time, so no GLib import library is
  needed.
- A boolean preference slot is `gboolean` before 4.0 and `bool` after; the
  runtime takes the slot's type from the binding's signature.
- Filter function definitions and names are leaked: Wireshark keeps them
  until the plugin's cleanup deregisters them.
- File type records, reader records and their strings, and codec names are
  leaked: Wireshark keeps the pointers for the process. An open file's
  reader state is boxed in `wth->priv` and dropped by the reader's close
  callback, which clears the pointer before Wireshark frees `priv`.

## Threads

Wireshark registers and dissects on one thread. The runtime's state is
behind a mutex anyway; the types holding Wireshark's pointers implement
`Send` only so the mutex can be a `static`.
