use crate::error::ProtocolError;

/// Non-zero 32-bit identifier tying bounded request chunks to their bounded response chunks (`D-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u32);

impl RequestId {
    /// Constructs a `RequestId`, rejecting `0`.
    pub fn new(raw: u32) -> Result<Self, ProtocolError> {
        if raw == 0 {
            return Err(ProtocolError::ZeroRequestId);
        }
        Ok(Self(raw))
    }

    /// Returns the raw `u32` representation.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Sanitized error codes emitted by Exit in response to destination, policy, or framing failures.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestErrorCode {
    PolicyDenied = 0x01,
    DnsFailed = 0x02,
    ConnectFailed = 0x03,
    Timeout = 0x04,
    PayloadTooLarge = 0x05,
    ProtocolViolation = 0x06,
    InternalError = 0x07,
}

impl RequestErrorCode {
    /// Parses a byte into `RequestErrorCode`, rejecting unrecognised error codes.
    pub fn from_u8(val: u8) -> Result<Self, ProtocolError> {
        match val {
            0x01 => Ok(Self::PolicyDenied),
            0x02 => Ok(Self::DnsFailed),
            0x03 => Ok(Self::ConnectFailed),
            0x04 => Ok(Self::Timeout),
            0x05 => Ok(Self::PayloadTooLarge),
            0x06 => Ok(Self::ProtocolViolation),
            0x07 => Ok(Self::InternalError),
            other => Err(ProtocolError::UnknownErrorCode(other)),
        }
    }

    /// Returns a human-readable sanitized summary that leaks zero internal network state.
    pub fn summary(self) -> &'static str {
        match self {
            Self::PolicyDenied => "destination blocked by exit SSRF policy",
            Self::DnsFailed => "destination DNS resolution failed at exit",
            Self::ConnectFailed => "exit connection to destination failed",
            Self::Timeout => "destination I/O timed out",
            Self::PayloadTooLarge => "payload exceeded 64 KiB bound",
            Self::ProtocolViolation => "malformed inner message payload",
            Self::InternalError => "exit internal failure",
        }
    }
}

/// Lifecycle state machine for a single bounded request/response exchange (`Decision D-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Idle,
    SendingRequest,
    AwaitingResponse,
    ReceivingResponse,
    Completed,
    Failed(RequestErrorCode),
}

impl RequestState {
    fn label(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::SendingRequest => "SendingRequest",
            Self::AwaitingResponse => "AwaitingResponse",
            Self::ReceivingResponse => "ReceivingResponse",
            Self::Completed => "Completed",
            Self::Failed(_) => "Failed",
        }
    }

    pub fn begin_request(&mut self) -> Result<(), ProtocolError> {
        match *self {
            Self::Idle => {
                *self = Self::SendingRequest;
                Ok(())
            }
            other => Err(ProtocolError::InvalidRequestTransition {
                from: other.label(),
                event: "BeginRequest",
            }),
        }
    }

    pub fn finish_request(&mut self) -> Result<(), ProtocolError> {
        match *self {
            Self::SendingRequest => {
                *self = Self::AwaitingResponse;
                Ok(())
            }
            other => Err(ProtocolError::InvalidRequestTransition {
                from: other.label(),
                event: "FinishRequest",
            }),
        }
    }

    pub fn begin_response(&mut self) -> Result<(), ProtocolError> {
        match *self {
            Self::AwaitingResponse => {
                *self = Self::ReceivingResponse;
                Ok(())
            }
            other => Err(ProtocolError::InvalidRequestTransition {
                from: other.label(),
                event: "BeginResponse",
            }),
        }
    }

    pub fn complete(&mut self) -> Result<(), ProtocolError> {
        match *self {
            Self::AwaitingResponse | Self::ReceivingResponse => {
                *self = Self::Completed;
                Ok(())
            }
            other => Err(ProtocolError::InvalidRequestTransition {
                from: other.label(),
                event: "Complete",
            }),
        }
    }

    pub fn fail(&mut self, code: RequestErrorCode) -> Result<(), ProtocolError> {
        match *self {
            Self::Completed | Self::Failed(_) => Err(ProtocolError::InvalidRequestTransition {
                from: self.label(),
                event: "Fail",
            }),
            _ => {
                *self = Self::Failed(code);
                Ok(())
            }
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed(_))
    }
}
