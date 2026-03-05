# Changelog

All notable changes to Attest are documented in this file.
The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2026-03-05

This is the production-ready release focusing on ZK-STARK hardening and deep integration into the VEX ecosystem.

### Added
- **Hardware-Rooted Zeroization**: The `vex-hardware` layer now enforces strict memory zeroization (`Zeroize` trait) for all sensitive cryptographic material.
- **Glassbox Provenance (VEX Binding)**:
  - Agent cognitive cycles and evolutionary mutations are now signed by hardware and bound to the VEX `AuditStore`.
  - JCS (RFC 8785) deterministic serialization for reproducible hardware signatures.
- **ZK-STARK Security Hardening**: 
  - Automated verifier circuitry protection against serialization corruption and public input forgery.
- **Pure-Go SQLite Bridge**: Removed CGO dependencies for absolute cross-platform portability.

### Changed
- Re-licensed project to **Apache 2.0** for robust patent protection.
- Fully revitalized documentation to align with VEX open-source standards.

---

## [v0.1.0-alpha] - 2026-02-05

### Added
- **ZK-STARK Integrity**: Integrated **Plonky3** framework with custom `AuditAir` constraint system.
- **Hardware-Backed Identity**: Native TPM2 (Linux) and CNG (Windows) support for sealed identities.

---

## [v0.0.1] - 2025-02-01

### Added
- **Core Strategy**: Implementation of Agent Identity (`aid:<hash>`) and Ed25519 signing.
- **Policy Engine**: Rule-based control for dangerous/destructive command execution.
- **Git Integration**: Pre-commit hooks and automated attestation for git workflows.
- **Multi-SDK Support**: Initial release of Python and JavaScript SDKs.
- **Storage**: Initial SQLite-based persistence layer.

---

## [v0.0.0] - 2024-12-01

- Initial development release and architectural proof-of-concept.
