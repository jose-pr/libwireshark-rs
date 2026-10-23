//! Wireshark's dissection engine in this process, for a program rather than
//! a plugin: dissect frames and read capture files with Wireshark's
//! dissectors and the plugins it loads, into the protocol tree and the
//! packet list's columns. Behind the `host` feature, on every release line
//! the crate builds for (3.0 to 4.6).
//!
//! ```no_run
//! use core::time::Duration;
//! use libwireshark::Encapsulation;
//! use libwireshark::host::{Host, HostConfig};
//!
//! let config = HostConfig {
//!     plugins: vec!["basic_dissector.dll".into()],
//!     ..HostConfig::default()
//! };
//! let mut host = Host::open(&config)?;
//! let frame = std::fs::read("frame.bin")?;
//! let dissected = host.dissect(&frame, Encapsulation::ETHERNET, Duration::ZERO)?;
//! println!("{:?}", dissected.get("foo.version"));
//! for frame in host.read("capture.pcapng".as_ref(), Some("foo"))? {
//!     let frame = frame?;
//!     println!("{}: {:?}", frame.frame, frame.column("Info"));
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Wireshark's state is the process's: it starts once, at the first
//! [`Host::open`], with that configuration, and one session is open at a
//! time. Never open one inside Wireshark (from a plugin): it refuses.

mod model;
mod session;
mod symbols;

pub use model::{Column, Dissected, HostConfig, Node};

use crate::Encapsulation;
use alloc::string::String;
use core::fmt;
use core::time::Duration;
use std::path::Path;

/// Why the host could not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostError {
    /// A session is already open in this process, or Wireshark itself
    /// runs it.
    AlreadyOpen,
    /// Wireshark started once with another configuration; it cannot start
    /// again in this process.
    Configured,
    /// A library or function of the running Wireshark was not found.
    Symbols(String),
    /// Wireshark did not start.
    Init(String),
    /// A plugin could not be loaded.
    Plugin {
        /// The plugin's path.
        path: String,
        /// Why.
        reason: String,
    },
    /// A preference was refused.
    Preference {
        /// The `name:value` given.
        preference: String,
        /// Why.
        reason: String,
    },
    /// A display filter did not compile.
    Filter(String),
    /// A capture file could not be opened or read.
    File(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOpen => {
                f.write_str("a session is already open, or Wireshark itself runs this process")
            }
            Self::Configured => {
                f.write_str("Wireshark already started in this process with another configuration")
            }
            Self::Symbols(what) => write!(f, "the running Wireshark lacks {what}"),
            Self::Init(why) => write!(f, "Wireshark did not start: {why}"),
            Self::Plugin { path, reason } => write!(f, "plugin {path}: {reason}"),
            Self::Preference { preference, reason } => {
                write!(f, "preference {preference}: {reason}")
            }
            Self::Filter(why) => write!(f, "display filter: {why}"),
            Self::File(why) => write!(f, "capture file: {why}"),
        }
    }
}

impl core::error::Error for HostError {}

/// Wireshark's dissection engine, hosted in this process.
///
/// Wireshark's state is per process: one session at a time, and the
/// plugins and preferences of the first [`open`](Self::open) stay for the
/// process (a later open must give the same configuration).
pub struct Host {
    session: session::Session,
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

impl Host {
    /// Starts Wireshark (the first time in the process) and opens a session.
    ///
    /// # Errors
    ///
    /// [`HostError`]: another session is open, the configuration differs
    /// from the first, or a plugin or preference is refused.
    pub fn open(config: &HostConfig) -> Result<Self, HostError> {
        Ok(Self {
            session: session::Session::open(config)?,
        })
    }

    /// Dissects one frame captured at `time` since the Unix epoch. Frames
    /// dissected one after the other share conversations.
    ///
    /// # Errors
    ///
    /// None today; the result stays fallible for Wireshark's own failures.
    pub fn dissect(
        &mut self,
        data: &[u8],
        encapsulation: Encapsulation,
        time: Duration,
    ) -> Result<Dissected, HostError> {
        Ok(self.session.dissect(data, encapsulation.to_raw(), time))
    }

    /// Reads the capture file at `path`, dissecting the frames that match
    /// `display_filter` (all when `None`). Reading starts a fresh capture:
    /// frame numbers and conversations start over.
    ///
    /// # Errors
    ///
    /// [`HostError::Filter`] or [`HostError::File`].
    pub fn read(
        &mut self,
        path: &Path,
        display_filter: Option<&str>,
    ) -> Result<Capture<'_>, HostError> {
        self.open_file(path, display_filter)?;
        Ok(Capture { host: self })
    }

    /// Opens a capture file for [`next_frame`](Self::next_frame), closing
    /// one already open: [`read`](Self::read) without the borrow, for a
    /// caller that keeps the host and the file together.
    ///
    /// # Errors
    ///
    /// [`HostError::Filter`] or [`HostError::File`].
    pub fn open_file(
        &mut self,
        path: &Path,
        display_filter: Option<&str>,
    ) -> Result<(), HostError> {
        self.session.open_file(path, display_filter)
    }

    /// The open file's next matching frame: `None` at its end, after an
    /// error, or with no file open.
    ///
    /// # Errors
    ///
    /// [`HostError::File`] when the file cannot be read further.
    pub fn next_frame(&mut self) -> Result<Option<Dissected>, HostError> {
        self.session.next()
    }
}

/// The frames of a capture file being read, dissected one at a time; an
/// error ends it.
pub struct Capture<'a> {
    host: &'a mut Host,
}

impl fmt::Debug for Capture<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capture").finish_non_exhaustive()
    }
}

impl Iterator for Capture<'_> {
    type Item = Result<Dissected, HostError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.host.next_frame().transpose()
    }
}
