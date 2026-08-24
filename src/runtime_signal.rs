//! Binary-owned process-signal injection for the Rhi daemon.

use core::{fmt, future::Future, pin::Pin};

/// One normalized process signal supplied by the Rhi binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiProcessSignal {
    Interrupt,
    #[cfg(unix)]
    Terminate,
}

impl RhiProcessSignal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            #[cfg(unix)]
            Self::Terminate => "terminate",
        }
    }
}

impl fmt::Display for RhiProcessSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Boxed wait returned by a binary-owned signal source.
pub type RhiProcessSignalFuture<'a> =
    Pin<Box<dyn Future<Output = Option<RhiProcessSignal>> + Send + 'a>>;

/// Process-signal source installed only by the executable boundary.
pub trait RhiProcessSignalSource: Send {
    fn next_signal(&mut self) -> RhiProcessSignalFuture<'_>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_signal_names_are_stable() {
        assert_eq!(RhiProcessSignal::Interrupt.as_str(), "interrupt");
        assert_eq!(RhiProcessSignal::Interrupt.to_string(), "interrupt");
        #[cfg(unix)]
        assert_eq!(RhiProcessSignal::Terminate.as_str(), "terminate");
    }
}
