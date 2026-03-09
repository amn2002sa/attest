use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_jcs;
use sha2::{Digest, Sha256};

/// Represents the different segments of an Attest message that require independent hashing.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SegmentType {
    Intent,
    Authority,
    Identity,
    Payload,
    Witness,
    Signature,
}

/// The Authority segment contains governance and replay protection data.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AuthoritySegment {
    /// 8-byte nonce for replay protection.
    pub nonce: u64,
    /// Reference to the trace root being authorized.
    pub trace_root: [u8; 32],
}

/// The Witness segment contains the append-only log record coordinates from CHORA.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct WitnessSegment {
    /// The CHORA node ID that issued the receipt.
    pub chora_node_id: String,
    /// The hash of the receipt on the append-only log.
    pub receipt_hash: String,
    /// Unix timestamp of the receipt issuance.
    pub timestamp: u64,
}

/// Helper for performing JCS-compliant hashing of message segments.
pub struct SegmentHasher;

impl SegmentHasher {
    /// Hashes a serializable segment using JCS canonicalization and SHA-256.
    /// Standard: SHA256(JCS(segment))
    pub fn hash<T: Serialize>(segment: &T) -> Result<[u8; 32]> {
        // 1. Canonicalize using JCS
        let canonical_json = serde_jcs::to_vec(segment)
            .map_err(|e| anyhow!("JCS canonicalization failed: {}", e))?;

        // 2. Compute SHA-256 digest
        let mut hasher = Sha256::new();
        hasher.update(&canonical_json);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }

    /// Convenience method to hash multiple segments and return their digests.
    pub fn hash_segments<T: Serialize>(
        segments: &[(SegmentType, T)],
    ) -> Result<Vec<([u8; 32], SegmentType)>> {
        let mut results = Vec::new();
        for (seg_type, data) in segments {
            let digest = Self::hash(data)?;
            results.push((digest, seg_type.clone()));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jcs_hashing_consistency() {
        // JCS ensures that key order doesn't affect the hash
        let val1 = json!({
            "id": "test",
            "value": 42,
            "meta": "data"
        });

        let val2 = json!({
            "meta": "data",
            "id": "test",
            "value": 42
        });

        let hash1 = SegmentHasher::hash(&val1).unwrap();
        let hash2 = SegmentHasher::hash(&val2).unwrap();

        assert_eq!(hash1, hash2, "JCS hashing must be order-independent");
    }

    #[test]
    fn test_segment_hashing() {
        let intent = json!({
            "action": "execute",
            "command": "whoami"
        });

        let hash = SegmentHasher::hash(&intent).expect("Should hash successfully");
        assert_ne!(hash, [0u8; 32], "Hash should not be empty");
    }

    #[test]
    fn test_authority_segment_hashing() {
        let auth = AuthoritySegment {
            nonce: 12345678,
            trace_root: [0u8; 32],
        };

        let hash = SegmentHasher::hash(&auth).expect("Should hash successfully");
        assert_ne!(hash, [0u8; 32], "Hash should not be empty");
    }
}
