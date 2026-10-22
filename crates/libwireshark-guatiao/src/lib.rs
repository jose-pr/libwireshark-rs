//! A Wireshark plugin that loads dissectors, tap listeners, display-filter
//! functions, capture formats and codecs written in any language guatiao
//! reaches, and registers each with Wireshark.
//!
//! When Wireshark loads it, the plugin scans `LIBWIRESHARK_GUATIAO_PATH`
//! and the `guatiao` directory of Wireshark's personal and global plugin
//! directories for libraries declaring one of the kinds of
//! `libwireshark-api`, adds every guatiao source file it finds there (such
//! as the Python bridge, serving the Python modules beside it), and asks
//! each provider to describe itself. Problems go to stderr;
//! `LIBWIRESHARK_GUATIAO_LOG` set to anything reports what loaded too.

extern crate alloc;

mod codec;
mod describe;
mod dirs;
mod file_type;
mod filter;
mod header;
mod host;
mod packet;
mod tap;

libwireshark::plugin!(dynamic = registrations);

fn registrations() -> libwireshark::dynamic::Registrations {
    host::registrations()
}
