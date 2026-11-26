use crate::cell::DestroyReason;
use crate::error::ProtocolError;

/// Non-zero 32-bit link-local circuit identifier.
///
/// The MSB (`0x8000_0000`) marks link-initiator ownership so adjacent peers allocating circuits
/// concurrently on one Noise link never choose colliding IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CircuitId(u32);

impl CircuitId {
    /// Constructs a `CircuitId`, rejecting `0`.
    pub fn new(raw: u32) -> Result<Self, ProtocolError> {
        if raw == 0 {
            return Err(ProtocolError::ZeroCircuitId);
        }
        Ok(Self(raw))
    }

    /// Sets or clears the link-initiator MSB bit from a 31-bit counter value.
    pub fn from_role_bits(
        lower_31_bits: u32,
        is_link_initiator: bool,
    ) -> Result<Self, ProtocolError> {
        let masked = lower_31_bits & 0x7FFF_FFFF;
        let raw = if is_link_initiator {
            masked | 0x8000_0000
        } else {
            masked
        };
        Self::new(raw)
    }

    /// Returns the raw `u32` representation.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Returns `true` when allocated by the link initiator (`MSB == 1`).
    pub fn is_initiator_owned(self) -> bool {
        (self.0 & 0x8000_0000) != 0
    }
}

/// Lifecycle state machine for a relay or client circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Building,
    Open,
    Closed(DestroyReason),
}

impl CircuitState {
    fn label(self) -> &'static str {
        match self {
            Self::Building => "Building",
            Self::Open => "Open",
            Self::Closed(_) => "Closed",
        }
    }

    /// Transitions `Building -> Open` once telescopic handshakes complete.
    pub fn mark_open(&mut self) -> Result<(), ProtocolError> {
        match *self {
            Self::Building => {
                *self = Self::Open;
                Ok(())
            }
            other => Err(ProtocolError::InvalidCircuitTransition {
                from: other.label(),
                event: "Open",
            }),
        }
    }

    /// Transitions `Building | Open -> Closed(reason)`. Closing an already closed circuit is rejected.
    pub fn destroy(&mut self, reason: DestroyReason) -> Result<(), ProtocolError> {
        match *self {
            Self::Building | Self::Open => {
                *self = Self::Closed(reason);
                Ok(())
            }
            Self::Closed(_) => Err(ProtocolError::InvalidCircuitTransition {
                from: "Closed",
                event: "Destroy",
            }),
        }
    }

    /// Returns `true` strictly while the circuit is open for forwarding.
    pub fn can_forward_data(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns `true` once torn down.
    pub fn is_closed(self) -> bool {
        matches!(self, Self::Closed(_))
    }
}
