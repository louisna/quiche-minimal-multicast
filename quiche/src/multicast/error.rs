//! Defines an error in minimal multicast QUIC.

/// An error related to the minimal multicast extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McError {
    /// Creation of the multicast flow failed.
    McFlow,
}

impl From<McError> for crate::Error {
    fn from(value: McError) -> Self {
        Self::Multicast(value)
    }
}
