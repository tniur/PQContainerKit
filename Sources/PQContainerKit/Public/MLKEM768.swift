//
//  MLKEM768.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import CryptoKit
import Foundation

/// ML-KEM-768 key types and key generation.
///
/// This namespace intentionally wraps CryptoKit types to keep the public API stable and
/// to allow swapping the backend in the future.
public enum MLKEM768 {
    /// A ML-KEM-768 public key.
    ///
    /// This key is safe to share (QR code, text, etc.) and can be imported by recipients.
    public struct PublicKey: Hashable, Sendable {
        /// Raw key bytes as defined by the underlying CryptoKit representation.
        public let rawRepresentation: Data

        /// Creates a public key from raw bytes.
        ///
        /// Use this initializer when importing a key from QR/text.
        ///
        /// - Parameter rawRepresentation: Raw bytes received from an external source.
        /// - Throws: `ContainerKitError.invalidKeyRepresentation`
        ///           if the bytes are not a valid ML-KEM-768 public key.
        public init(rawRepresentation: Data) throws {
            do {
                _ = try CryptoKitMLKEM768Adapter.makePublicKey(fromRaw: rawRepresentation)
                self.rawRepresentation = rawRepresentation
            } catch {
                throw ContainerKitError.invalidKeyRepresentation
            }
        }

        /// Creates a public key from a Base64-encoded string.
        ///
        /// - Parameter base64: Base64 string representation of the public key.
        /// - Throws: `ContainerKitError.invalidBase64` if Base64 decoding fails,
        ///           or `ContainerKitError.invalidKeyRepresentation` if decoded bytes are not a valid key.
        public init(base64: String) throws {
            guard let data = Data(base64Encoded: base64) else {
                throw ContainerKitError.invalidBase64
            }
            try self.init(rawRepresentation: data)
        }

        /// Base64 representation of `rawRepresentation`.
        ///
        /// Intended for QR/text export.
        public var base64: String {
            rawRepresentation.base64EncodedString()
        }

        /// Fingerprint of this public key: `SHA-256(rawRepresentation)`.
        public var fingerprint: Fingerprint {
            Fingerprint.fromPublicKeyRaw(rawRepresentation)
        }

        /// Internal initializer for keys originating from CryptoKit (already validated).
        init(uncheckedRawRepresentation: Data) {
            rawRepresentation = uncheckedRawRepresentation
        }
    }

    /// A ML-KEM-768 private key.
    ///
    /// This is a secret key. It should not be exported or logged.
    public struct PrivateKey: Sendable {
        fileprivate let cryptoKitPrivateKey: CryptoKit.MLKEM768.PrivateKey

        fileprivate init(_ pk: CryptoKit.MLKEM768.PrivateKey) {
            cryptoKitPrivateKey = pk
        }

        /// The corresponding public key for this private key.
        public var publicKey: PublicKey {
            let raw = CryptoKitMLKEM768Adapter.publicKeyRaw(from: cryptoKitPrivateKey)
            return PublicKey(uncheckedRawRepresentation: raw)
        }
    }

    /// A generated ML-KEM-768 key pair.
    public struct KeyPair: Sendable {
        /// Public key (shareable).
        public let publicKey: PublicKey

        /// Private key (secret).
        public let privateKey: PrivateKey
    }

    /// Generates a new ML-KEM-768 key pair.
    ///
    /// - Returns: A new `KeyPair` containing a private key and its public key.
    /// - Throws: `Error.keyGenerationFailed` if platform key generation fails.
    public static func generateKeyPair() throws -> KeyPair {
        do {
            let sk = try CryptoKitMLKEM768Adapter.generatePrivateKey()
            let privateKey = PrivateKey(sk)

            return KeyPair(publicKey: privateKey.publicKey, privateKey: privateKey)
        } catch {
            throw ContainerKitError.keyGenerationFailed
        }
    }
}

// MARK: - KEM Ciphertext

public extension MLKEM768 {
    /// A validated ML-KEM-768 ciphertext.
    ///
    /// The ciphertext has a fixed size for ML-KEM-768.
    struct Ciphertext: Hashable, Sendable {
        /// Fixed ciphertext size (bytes) for ML-KEM-768.
        public static let byteCount = 1088

        /// Raw ciphertext bytes.
        public let rawRepresentation: Data

        /// Creates a ciphertext from raw bytes.
        ///
        /// - Throws: `ContainerKitError.invalidCiphertextRepresentation`
        ///   if the byte count doesn't match ML-KEM-768 ciphertext size.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == Self.byteCount else {
                throw ContainerKitError.invalidCiphertextRepresentation
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}

// MARK: - Internal CryptoKit bridges

internal extension MLKEM768.PublicKey {
    /// Returns the underlying CryptoKit public key.
    ///
    /// This should never fail for instances created through the public initializers
    /// (they validate the raw bytes). If it fails, treat it as invalid representation.
    func cryptoKitKey() throws -> CryptoKit.MLKEM768.PublicKey {
        do {
            return try CryptoKitMLKEM768Adapter.makePublicKey(fromRaw: rawRepresentation)
        } catch {
            throw ContainerKitError.invalidKeyRepresentation
        }
    }
}

internal extension MLKEM768.PrivateKey {
    /// Returns the underlying CryptoKit private key.
    var cryptoKitKey: CryptoKit.MLKEM768.PrivateKey {
        cryptoKitPrivateKey
    }
}
