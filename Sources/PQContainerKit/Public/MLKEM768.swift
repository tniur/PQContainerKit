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
        /// - Throws: `Error.invalidKeyRepresentation`
        ///           if the bytes are not a valid ML-KEM-768 public key.
        public init(rawRepresentation: Data) throws {
            do {
                _ = try CryptoKitMLKEM768Adapter.makePublicKey(fromRaw: rawRepresentation)
                self.rawRepresentation = rawRepresentation
            } catch {
                throw Error.invalidKeyRepresentation
            }
        }

        /// Creates a public key from a Base64-encoded string.
        ///
        /// - Parameter base64: Base64 string representation of the public key.
        /// - Throws: `Error.invalidBase64` if Base64 decoding fails,
        ///           or `Error.invalidKeyRepresentation` if decoded bytes are not a valid key.
        public init(base64: String) throws {
            guard let data = Data(base64Encoded: base64) else {
                throw Error.invalidBase64
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
            throw Error.keyGenerationFailed
        }
    }
}
