#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("service error: {0}")]
    Service(String),
    #[error("not found")]
    NotFound,
    #[error("not connected")]
    NotConnected,
    #[error("timeout")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
