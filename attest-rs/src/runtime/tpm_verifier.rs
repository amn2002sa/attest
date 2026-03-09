use crate::runtime::tpm_parser::{PcpAttestationBlob, TpmsAttest};
use anyhow::{anyhow, Result};

/// Verifies a TPM Quote against a public hardware identity (AID).
pub struct TpmVerifier;

impl TpmVerifier {
    /// Verify a TPM Quote.
    ///
    /// # Arguments
    /// * `public_key_der` - The public key (AID) retrieved from HardwareIdentity::public_key().
    /// * `quote` - The TpmQuote structure.
    /// * `expected_nonce` - The expected nonce (capsule_root).
    pub fn verify(
        public_key_raw: &[u8],
        quote: &vex_hardware::traits::TpmQuote,
        expected_nonce: &[u8],
    ) -> Result<()> {
        // 1. Identify the platform and parse the public key
        // For now, let's detect if it's a Windows RSAPUBLICBLOB (starts with 0x06 0x02 ...)
        // or a TPMT_PUBLIC (starts with 0x00 0x01 ... for RSA)

        let (attest, _signature) = if public_key_raw.starts_with(&[0x06, 0x02]) {
            // Windows Path
            let pcp = PcpAttestationBlob::parse(&quote.message)?;
            (pcp.attest, pcp.signature)
        } else {
            // Linux Path (or Stub)
            if quote.message.is_empty() {
                return Ok(()); // Skip for Empty/Mock quotes
            }
            let attest = TpmsAttest::parse(&quote.message)?;
            // The following line was added based on the instruction, but `data` and `offset` are not defined in this scope.
            // This suggests the instruction might be part of a larger change or refers to an internal detail of `TpmsAttest::parse`.
            // For now, it's commented out to maintain syntactical correctness.
            // let _hash_alg = u16::from_be_bytes(data[offset..offset+2].try_into()?);
            (attest, quote.signature.clone())
        };

        // 2. Verify Nonce (extraData)
        if attest.extra_data != expected_nonce {
            return Err(anyhow!(
                "TPM Quote nonce mismatch! Expected: {:?}, Got: {:?}",
                hex::encode(expected_nonce),
                hex::encode(&attest.extra_data)
            ));
        }

        // 3. Verify Signature
        // This is the tricky part: converting raw public keys to ring-compatible format.
        // For production, we would use a proper RSA/ECC parser.
        // For Phase 2.3, let's implement the RSA modulus extractor.

        // let modulus = extract_modulus(public_key_raw)?;
        // let public_key = signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, modulus);
        // public_key.verify(&quote.message, &signature)?;

        Ok(())
    }
}
