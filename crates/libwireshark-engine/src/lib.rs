#![doc = include_str!("../README.md")]
#![warn(missing_docs, missing_debug_implementations)]

extern crate alloc;

#[cfg(engine)]
mod epan;
#[cfg(feature = "provider")]
mod provider;
#[cfg(engine)]
mod symbols;

use core::fmt;
use core::time::Duration;
use std::path::Path;

pub use libwireshark_api::engine::{Column, Dissected, EngineConfig, Node};

/// Why the engine could not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineError {
    /// This build's release line has no engine (it needs 4.6 or later).
    Unsupported,
    /// A session is already open in this process.
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

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("the engine needs a build for Wireshark 4.6 or later"),
            Self::AlreadyOpen => f.write_str("a session is already open in this process"),
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

impl core::error::Error for EngineError {}

/// A frame's link-layer type (`WTAP_ENCAP_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Encapsulation(pub i32);

impl Encapsulation {
    /// Ethernet.
    pub const ETHERNET: Self = Self(1);
    /// Raw IP, v4 or v6 by its version field.
    pub const RAW_IP: Self = Self(7);
}

/// Wireshark's dissection engine, running in this process.
///
/// Wireshark's state is per process: one session at a time, and the
/// plugins and preferences of the first [`open`](Self::open) stay for the
/// process (a later open must give the same configuration).
pub struct Engine {
    #[cfg(engine)]
    session: epan::Session,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Engine {
    /// Starts Wireshark (the first time in the process) and opens a session.
    ///
    /// # Errors
    ///
    /// [`EngineError`]: another session is open, the configuration differs
    /// from the first, a plugin or preference is refused, or this build has
    /// no engine.
    pub fn open(config: &EngineConfig) -> Result<Self, EngineError> {
        #[cfg(engine)]
        {
            Ok(Self {
                session: epan::Session::open(config)?,
            })
        }
        #[cfg(not(engine))]
        {
            let _ = config;
            Err(EngineError::Unsupported)
        }
    }

    /// Dissects one frame captured at `time` since the Unix epoch. Frames
    /// dissected one after the other share conversations.
    ///
    /// # Errors
    ///
    /// None today; the result stays fallible for the engine's own failures.
    pub fn dissect(
        &mut self,
        data: &[u8],
        encapsulation: Encapsulation,
        time: Duration,
    ) -> Result<Dissected, EngineError> {
        #[cfg(engine)]
        {
            Ok(self.session.dissect(data, encapsulation.0, time))
        }
        #[cfg(not(engine))]
        {
            let _ = (data, encapsulation, time);
            Err(EngineError::Unsupported)
        }
    }

    /// Reads the capture file at `path`, dissecting the frames that match
    /// `display_filter` (all when `None`). Reading starts a fresh capture:
    /// frame numbers and conversations start over.
    ///
    /// # Errors
    ///
    /// [`EngineError::Filter`] or [`EngineError::File`].
    pub fn read(
        &mut self,
        path: &Path,
        display_filter: Option<&str>,
    ) -> Result<Capture<'_>, EngineError> {
        self.open_file(path, display_filter)?;
        Ok(Capture { engine: self })
    }

    /// Opens a capture file for [`next_frame`](Self::next_frame), closing
    /// one already open.
    pub(crate) fn open_file(
        &mut self,
        path: &Path,
        display_filter: Option<&str>,
    ) -> Result<(), EngineError> {
        #[cfg(engine)]
        {
            self.session.open_file(path, display_filter)
        }
        #[cfg(not(engine))]
        {
            let _ = (path, display_filter);
            Err(EngineError::Unsupported)
        }
    }

    /// The open file's next matching frame: `None` at its end, after an
    /// error, or with no file open.
    pub(crate) fn next_frame(&mut self) -> Result<Option<Dissected>, EngineError> {
        #[cfg(engine)]
        {
            self.session.next()
        }
        #[cfg(not(engine))]
        {
            Ok(None)
        }
    }
}

/// The frames of a capture file being read, dissected one at a time; an
/// error ends it.
pub struct Capture<'a> {
    engine: &'a mut Engine,
}

impl fmt::Debug for Capture<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capture").finish_non_exhaustive()
    }
}

impl Iterator for Capture<'_> {
    type Item = Result<Dissected, EngineError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.engine.next_frame().transpose()
    }
}
