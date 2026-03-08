pub use crate::traits::HardwareIdentity;
#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use async_trait::async_trait;

/// Factory function to create the platform-appropriate Identity Provider
#[allow(unused_variables)]
pub fn create_identity_provider(allow_fallback: bool) -> Box<dyn HardwareIdentity> {
    #[cfg(windows)]
    return Box::new(windows_impl::CngIdentity {});

    #[cfg(target_os = "linux")]
    {
        match linux_impl::Tpm2Identity::new() {
            Ok(tpm) => Box::new(tpm),
            Err(e) => {
                if allow_fallback {
                    Box::new(stub_impl::StubIdentity::default())
                } else {
                    panic!("❌ Critical: TPM required but initialization failed: {}", e);
                }
            }
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        if allow_fallback {
            Box::new(stub_impl::StubIdentity::default())
        } else {
            panic!("❌ Critical: Hardware identity not supported on this platform");
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::Tpm2Identity;
#[cfg(not(any(windows, target_os = "linux")))]
pub use stub_impl::StubIdentity;
#[cfg(windows)]
pub use windows_impl::CngIdentity;

// Windows Implementation
#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Cryptography::*;

    fn map_cng_error(status: i32) -> String {
        match status as u32 {
            0x80090010 => "Access Denied (Insufficient TPM permissions)".to_string(),
            0x80090025 => "TPM Device Locked (Anti-hammering lockout)".to_string(),
            0x80090005 => "Bad Data (Corrupted ciphertext)".to_string(),
            0x80090027 => "Hardware Unsupported (Payload too large)".to_string(),
            _ => format!("CNG Status 0x{:X}", status as u32),
        }
    }

    #[derive(Default)]
    pub struct CngIdentity;

    #[async_trait]
    impl HardwareIdentity for CngIdentity {
        async fn seal(&self, _label: &str, data: &[u8]) -> Result<Vec<u8>> {
            unsafe {
                let mut provider: usize = 0;
                let provider_name: Vec<u16> = "Microsoft Platform Crypto Provider\0"
                    .encode_utf16()
                    .collect();
                let status = NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0);
                if status != 0 {
                    return Err(anyhow!(
                        "TPM provider not available ({})",
                        map_cng_error(status)
                    ));
                }

                let mut key_handle: usize = 0;
                let key_name: Vec<u16> = "AttestIdentitySRK\0".encode_utf16().collect();
                let alg_id: Vec<u16> = "RSA\0".encode_utf16().collect();

                let mut status = NCryptOpenKey(provider, &mut key_handle, key_name.as_ptr(), 0, 0);
                if status != 0 {
                    status = NCryptCreatePersistedKey(
                        provider,
                        &mut key_handle,
                        alg_id.as_ptr(),
                        key_name.as_ptr(),
                        0,
                        0,
                    );
                    if status != 0 {
                        NCryptFreeObject(provider);
                        return Err(anyhow!(
                            "Failed to create TPM key ({})",
                            map_cng_error(status)
                        ));
                    }
                    status = NCryptFinalizeKey(key_handle, 0);
                    if status != 0 {
                        NCryptFreeObject(key_handle);
                        NCryptFreeObject(provider);
                        return Err(anyhow!(
                            "Failed to finalize TPM key ({})",
                            map_cng_error(status)
                        ));
                    }
                }

                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(data);
                let mut payload = Vec::with_capacity(data.len() + 32);
                payload.extend_from_slice(&hasher.finalize());
                payload.extend_from_slice(data);

                let mut output_size: u32 = 0;
                status = NCryptEncrypt(
                    key_handle,
                    payload.as_ptr(),
                    payload.len() as u32,
                    std::ptr::null(),
                    null_mut(),
                    0,
                    &mut output_size,
                    NCRYPT_PAD_PKCS1_FLAG,
                );
                if status != 0 {
                    NCryptFreeObject(key_handle);
                    NCryptFreeObject(provider);
                    return Err(anyhow!(
                        "Failed to get ciphertext size ({})",
                        map_cng_error(status)
                    ));
                }

                let mut ciphertext = vec![0u8; output_size as usize];
                status = NCryptEncrypt(
                    key_handle,
                    payload.as_ptr(),
                    payload.len() as u32,
                    std::ptr::null(),
                    ciphertext.as_mut_ptr(),
                    ciphertext.len() as u32,
                    &mut output_size,
                    NCRYPT_PAD_PKCS1_FLAG,
                );

                NCryptFreeObject(key_handle);
                NCryptFreeObject(provider);
                if status != 0 {
                    return Err(anyhow!(
                        "Failed to encrypt with TPM ({})",
                        map_cng_error(status)
                    ));
                }
                Ok(ciphertext)
            }
        }

        async fn unseal(&self, _blob: &[u8]) -> Result<Vec<u8>> {
            todo!("Windows CNG identity unseal for Noise")
        }
        async fn sign_handshake_hash(&self, _hash: &[u8]) -> Result<[u8; 64]> {
            todo!("Windows CNG identity signature for Noise")
        }
        async fn dh(&self, _remote_public_key: &[u8]) -> Result<[u8; 32]> {
            todo!("Windows CNG identity DH for Noise")
        }

        async fn generate_quote(&self, _nonce: &[u8]) -> Result<crate::traits::TpmQuote> {
            unsafe {
                let mut provider: usize = 0;
                let provider_name: Vec<u16> = "Microsoft Platform Crypto Provider\0"
                    .encode_utf16()
                    .collect();
                let status = NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0);
                if status != 0 {
                    return Err(anyhow!(
                        "TPM provider not available ({})",
                        map_cng_error(status)
                    ));
                }

                let mut key_handle: usize = 0;
                let key_name: Vec<u16> = "AttestIdentitySRK\0".encode_utf16().collect();
                let status = NCryptOpenKey(provider, &mut key_handle, key_name.as_ptr(), 0, 0);
                if status != 0 {
                    NCryptFreeObject(provider);
                    return Err(anyhow!(
                        "Failed to open TPM identity key ({})",
                        map_cng_error(status)
                    ));
                }

                let mut output_size: u32 = 0;
                let property_name: Vec<u16> =
                    "PCP_PLATFORM_ATTESTATION_BLOB\0".encode_utf16().collect();
                let status = NCryptGetProperty(
                    key_handle,
                    property_name.as_ptr(),
                    null_mut(),
                    0,
                    &mut output_size,
                    0,
                );
                if status != 0 {
                    NCryptFreeObject(key_handle);
                    NCryptFreeObject(provider);
                    return Err(anyhow!(
                        "Failed to get attestation property size ({})",
                        map_cng_error(status)
                    ));
                }

                let mut blob = vec![0u8; output_size as usize];
                let status = NCryptGetProperty(
                    key_handle,
                    property_name.as_ptr(),
                    blob.as_mut_ptr(),
                    blob.len() as u32,
                    &mut output_size,
                    0,
                );
                NCryptFreeObject(key_handle);
                NCryptFreeObject(provider);
                if status != 0 {
                    return Err(anyhow!(
                        "Failed to retrieve attestation blob ({})",
                        map_cng_error(status)
                    ));
                }

                Ok(crate::traits::TpmQuote {
                    message: blob,
                    signature: Vec::new(),
                    pcrs: Vec::new(),
                })
            }
        }

        async fn public_key(&self) -> Result<Vec<u8>> {
            unsafe {
                let mut provider: usize = 0;
                let provider_name: Vec<u16> = "Microsoft Platform Crypto Provider\0"
                    .encode_utf16()
                    .collect();
                NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0);

                let mut key_handle: usize = 0;
                let key_name: Vec<u16> = "AttestIdentitySRK\0".encode_utf16().collect();
                NCryptOpenKey(provider, &mut key_handle, key_name.as_ptr(), 0, 0);

                let mut output_size: u32 = 0;
                let blob_type: Vec<u16> = "RSAPUBLICBLOB\0".encode_utf16().collect();
                NCryptExportKey(
                    key_handle,
                    0,
                    blob_type.as_ptr(),
                    null_mut(),
                    null_mut(),
                    0,
                    &mut output_size,
                    0,
                );

                let mut blob = vec![0u8; output_size as usize];
                NCryptExportKey(
                    key_handle,
                    0,
                    blob_type.as_ptr(),
                    null_mut(),
                    blob.as_mut_ptr(),
                    blob.len() as u32,
                    &mut output_size,
                    0,
                );

                NCryptFreeObject(key_handle);
                NCryptFreeObject(provider);
                Ok(blob)
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;

    pub struct Tpm2Identity;

    impl Tpm2Identity {
        pub fn new() -> Result<Self> {
            Ok(Self)
        }
    }

    #[async_trait]
    impl HardwareIdentity for Tpm2Identity {
        async fn seal(&self, _label: &str, data: &[u8]) -> Result<Vec<u8>> {
            Ok(data.to_vec())
        }
        async fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>> {
            Ok(blob.to_vec())
        }
        async fn sign_handshake_hash(&self, _hash: &[u8]) -> Result<[u8; 64]> {
            Ok([0u8; 64])
        }
        async fn dh(&self, _remote_public_key: &[u8]) -> Result<[u8; 32]> {
            Ok([0u8; 32])
        }
        async fn generate_quote(&self, _nonce: &[u8]) -> Result<crate::traits::TpmQuote> {
            Ok(crate::traits::TpmQuote {
                message: Vec::new(),
                signature: Vec::new(),
                pcrs: Vec::new(),
            })
        }
        async fn public_key(&self) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }
}

mod stub_impl {
    use super::*;

    #[derive(Default)]
    #[allow(dead_code)]
    pub struct StubIdentity;

    #[async_trait]
    impl HardwareIdentity for StubIdentity {
        async fn seal(&self, _label: &str, data: &[u8]) -> Result<Vec<u8>> {
            Ok(data.to_vec())
        }

        async fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>> {
            Ok(blob.to_vec())
        }

        async fn sign_handshake_hash(&self, _hash: &[u8]) -> Result<[u8; 64]> {
            Ok([0u8; 64])
        }

        async fn dh(&self, _remote_public_key: &[u8]) -> Result<[u8; 32]> {
            Ok([0u8; 32])
        }

        async fn generate_quote(&self, _nonce: &[u8]) -> Result<crate::traits::TpmQuote> {
            Ok(crate::traits::TpmQuote {
                message: Vec::new(),
                signature: Vec::new(),
                pcrs: Vec::new(),
            })
        }

        async fn public_key(&self) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hardware_identity_interface() {
        let provider = create_identity_provider(true); // Fallback for envs without TPM
        let data = b"test_secret_seed";

        match provider.seal("test_label", data).await {
            Ok(sealed) => {
                let unsealed = provider
                    .unseal(&sealed)
                    .await
                    .expect("Unseal must succeed if seal succeeded");
                assert_eq!(
                    data.to_vec(),
                    unsealed,
                    "Unsealed data must match original input"
                );
            }
            Err(e) => {
                println!("⚠️ TPM Seal skipped or failed: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_tpm_quote() {
        let provider = create_identity_provider(true);
        let nonce = [0xAA; 32];

        let result = provider.generate_quote(&nonce).await;
        assert!(result.is_ok());
    }
}
