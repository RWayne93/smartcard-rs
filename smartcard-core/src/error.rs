use std::error::Error;
use std::fmt;
use std::time::Duration;

pub type Result<T> = std::result::Result<T, SmartcardError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmartcardError {
    Timeout {
        operation: &'static str,
        timeout: Duration,
    },
    Transport(String),
    Protocol(String),
    InvalidArgument(String),
    NotFound(String),
    WorkerClosed,
    Unsupported(String),
}

impl SmartcardError {
    pub fn timeout(operation: &'static str, timeout: Duration) -> Self {
        Self::Timeout { operation, timeout }
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }
}

impl fmt::Display for SmartcardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout { operation, timeout } => {
                write!(f, "{operation} timed out after {}ms", timeout.as_millis())
            }
            Self::Transport(message) => write!(f, "transport error: {message}"),
            Self::Protocol(message) => write!(f, "protocol error: {message}"),
            Self::InvalidArgument(message) => write!(f, "invalid argument: {message}"),
            Self::NotFound(message) => write!(f, "not found: {message}"),
            Self::WorkerClosed => write!(f, "worker closed before responding"),
            Self::Unsupported(message) => write!(f, "unsupported: {message}"),
        }
    }
}

impl Error for SmartcardError {}
