//
//  ContainerKitError.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

/// Public error type for PQContainerKit.
///
/// Errors are coarse-grained by design and do not expose low-level cryptographic failure details.
public enum ContainerKitError: Error, Equatable, Sendable {
    // MARK: - Key import/export

    /// The provided Base64 string is not valid Base64.
    case invalidBase64
    /// The provided key bytes are not a valid representation for the expected key type.
    case invalidKeyRepresentation
    /// Key generation failed (platform API error).
    case keyGenerationFailed

    // MARK: - ML-KEM

    /// KEM encapsulation failed (platform cryptography error).
    case kemEncapsulationFailed
    /// KEM decapsulation failed (platform cryptography error).
    case kemDecapsulationFailed
    /// The provided ciphertext bytes are not a valid representation for ML-KEM ciphertext.
    case invalidCiphertextRepresentation

    // MARK: - KDF / AEAD

    /// Invalid requested output length for KDF.
    case invalidKDFOutputLength
    /// AES-GCM nonce length is invalid (must be 12 bytes).
    case invalidNonceLength
    /// AES-GCM tag length is invalid (must be 16 bytes).
    case invalidTagLength
    /// AEAD operation failed (authentication failure or other cryptographic error).
    case aeadFailed
    /// wrappedDEK has an invalid representation (length/format mismatch).
    case invalidWrappedDEKRepresentation
}
