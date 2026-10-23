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
//!
//! The other way round, the library is also a guatiao provider of
//! `wireshark_host`: a guatiao host (such as the `libwireshark` Python
//! package) loads it to run Wireshark's engine in its own process.

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
mod wireshark_host;

libwireshark::plugin!(dynamic = registrations);

// The same library, loaded by a guatiao host rather than Wireshark, serves
// Wireshark itself, hosted in that process.
guatiao::providers!(wireshark_host::WiresharkHost);

fn registrations() -> libwireshark::dynamic::Registrations {
    host::registrations()
}
