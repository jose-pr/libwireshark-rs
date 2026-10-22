//! A Wireshark plugin that loads dissectors written in any language guatiao
//! reaches, and registers each as a protocol.
//!
//! When Wireshark loads it, the plugin scans `LIBWIRESHARK_GUATIAO_PATH`
//! and the `guatiao` directory of Wireshark's personal and global plugin
//! directories for libraries declaring `kind=wireshark_dissector`, adds
//! every guatiao source file it finds there (such as the Python bridge,
//! serving the Python modules beside it), and asks each provider for its
//! [`Description`](libwireshark_api::Description). Problems go to stderr;
//! `LIBWIRESHARK_GUATIAO_LOG` set to anything reports what loaded too.

extern crate alloc;

mod describe;
mod dirs;
mod header;
mod host;
mod packet;

libwireshark::plugin!(dynamic = protocols);

fn protocols() -> Vec<libwireshark::dynamic::Protocol> {
    host::protocols()
}
