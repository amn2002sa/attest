use anyhow::Result;
use async_trait::async_trait;

/// Abstraction for Hardware-Backed Identity (TPM, Secure Enclave, etc.)
#[async_trait]
pub trait HardwareIdentity: Send + Sync {
    /// Seal a secret (e.g. key seed) to the hardware.
    /// The `label` allows distinct secrets to be stored (e.g. "identity_seed").
    async fn seal(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Unseal a secret using the hardware's private key.
    /// This should fail if the integrity of the machine state is compromised (if PCRs are checked).
    async fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>>;
}

/// Abstraction for Network Monitoring (Process/Socket correlation)
pub trait NetworkWatchman: Send + Sync {
    /// Get a list of active connections for a specific process tree (PID + children).
    fn get_process_connections(&self, pid: u32) -> Result<Vec<ConnectionInfo>>;
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub pid: u32,
    pub process_name: String,
}
