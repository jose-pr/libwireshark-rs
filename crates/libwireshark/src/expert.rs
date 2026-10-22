//! Expert info: findings a dissector attaches to a packet, listed in
//! Wireshark's Expert Information dialog and filterable as `_ws.expert`.

/// One kind of finding a protocol can report, registered with the protocol.
///
/// Its abbreviation is registered below the protocol's filter name like a
/// field's: `bad_length` in protocol `foo` is `foo.bad_length`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Expert {
    abbrev: &'static str,
    group: ExpertGroup,
    severity: Severity,
    summary: &'static str,
}

impl Expert {
    /// A finding filtered as `abbrev`, in `group`, at `severity`, shown as `summary`.
    pub const fn new(
        abbrev: &'static str,
        group: ExpertGroup,
        severity: Severity,
        summary: &'static str,
    ) -> Self {
        Self {
            abbrev,
            group,
            severity,
            summary,
        }
    }

    /// The abbreviation as declared, relative or full.
    pub const fn abbrev(&self) -> &'static str {
        self.abbrev
    }

    /// The finding's group.
    pub const fn group(&self) -> ExpertGroup {
        self.group
    }

    /// The finding's severity.
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// The text shown when no other text is given.
    pub const fn summary(&self) -> &'static str {
        self.summary
    }
}

/// How serious a finding is, Wireshark's `PI_*` severities.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    /// A packet comment.
    Comment,
    /// Normal workflow, such as a connection being set up.
    Chat,
    /// Notable but usual, such as an error response.
    Note,
    /// Unusual, such as an unexpected value.
    Warning,
    /// A serious problem, such as a malformed packet.
    Error,
}

impl Severity {
    pub(crate) const fn bits(self) -> u32 {
        match self {
            Self::Comment => 0x0010_0000,
            Self::Chat => 0x0020_0000,
            Self::Note => 0x0040_0000,
            Self::Warning => 0x0060_0000,
            Self::Error => 0x0080_0000,
        }
    }
}

/// What a finding is about, Wireshark's `PI_*` groups.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExpertGroup {
    /// A checksum.
    Checksum,
    /// Sequence numbers.
    Sequence,
    /// A response code.
    ResponseCode,
    /// A request code.
    RequestCode,
    /// Data left undecoded.
    Undecoded,
    /// Reassembly.
    Reassemble,
    /// A malformed packet.
    Malformed,
    /// Debugging.
    Debug,
    /// A violation of the protocol's specification.
    Protocol,
    /// A security problem.
    Security,
    /// A packet comment.
    Comments,
    /// Decryption.
    Decryption,
    /// An assumption the dissector made.
    Assumption,
    /// A deprecated feature in use.
    Deprecated,
}

impl ExpertGroup {
    pub(crate) const fn bits(self) -> u32 {
        (match self {
            Self::Checksum => 0x01,
            Self::Sequence => 0x02,
            Self::ResponseCode => 0x03,
            Self::RequestCode => 0x04,
            Self::Undecoded => 0x05,
            Self::Reassemble => 0x06,
            Self::Malformed => 0x07,
            Self::Debug => 0x08,
            Self::Protocol => 0x09,
            Self::Security => 0x0a,
            Self::Comments => 0x0b,
            Self::Decryption => 0x0c,
            Self::Assumption => 0x0d,
            Self::Deprecated => 0x0e,
        }) << 24
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpertGroup, Severity};
    use crate::sys;

    #[test]
    fn severities_and_groups_carry_wiresharks_values() {
        assert_eq!(Severity::Warning.bits(), sys::PI_WARN);
        assert_eq!(Severity::Error.bits(), sys::PI_ERROR);
        assert_eq!(Severity::Comment.bits(), sys::PI_COMMENT);
        assert_eq!(ExpertGroup::Malformed.bits(), sys::PI_MALFORMED);
        assert_eq!(ExpertGroup::Deprecated.bits(), sys::PI_DEPRECATED);
        assert_eq!(ExpertGroup::Comments.bits(), sys::PI_COMMENTS_GROUP);
    }
}
