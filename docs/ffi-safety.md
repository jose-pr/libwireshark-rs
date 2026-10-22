# FFI safety

`libwireshark-sys` is raw C: every function is `unsafe`. `libwireshark`
wraps both sides of the boundary, Wireshark calling the plugin and the
plugin calling Wireshark, so a plugin needs no `unsafe`. Its `unsafe`
is in `src/packet.rs` and the `src/plugin/` module; a test fails if any
other file gains some.

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

## Threads

Wireshark registers and dissects on one thread. The runtime's state is
behind a mutex anyway; the types holding Wireshark's pointers implement
`Send` only so the mutex can be a `static`.
