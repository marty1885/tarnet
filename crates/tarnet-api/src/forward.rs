//! Domain-separated authentication for daemon port forwarding.
use serde::{Deserialize, Serialize};
use crate::types::ServiceId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub identity: Option<String>,
    pub target: ServiceId,
    pub challenge: [u8; 32],
    pub request: Vec<u8>,
}

impl SignRequest {
    pub fn message(&self) -> Vec<u8> {
        let mut out = b"tarnet forwarding authentication v1\0".to_vec();
        out.extend_from_slice(self.target.as_bytes());
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&(self.request.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.request);
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub source: ServiceId,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}
