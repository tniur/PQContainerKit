//
//  XWing.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 11.03.2026.
//

import CryptoKit
import Foundation

public enum XWing {
    public struct PublicKey: Hashable, Sendable {
        public var base64: String {
            rawRepresentation.base64EncodedString()
        }

        public var fingerprint: Fingerprint {
            Fingerprint.fromPublicKeyRaw(rawRepresentation)
        }

        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            do {
                _ = try CryptoKitXWingAdapter.makePublicKey(fromRaw: rawRepresentation)
                self.rawRepresentation = rawRepresentation
            } catch {
                throw ContainerKitError.invalidKeyRepresentation
            }
        }

        public init(base64: String) throws {
            guard let data = Data(base64Encoded: base64) else {
                throw ContainerKitError.invalidBase64
            }

            try self.init(rawRepresentation: data)
        }

        init(uncheckedRawRepresentation: Data) {
            rawRepresentation = uncheckedRawRepresentation
        }
    }

    public struct PrivateKey: Sendable {
        public var publicKey: PublicKey {
            let raw = CryptoKitXWingAdapter.publicKeyRaw(from: cryptoKitPrivateKey)
            return PublicKey(uncheckedRawRepresentation: raw)
        }

        fileprivate let cryptoKitPrivateKey: CryptoKit.XWingMLKEM768X25519.PrivateKey

        fileprivate init(_ pk: CryptoKit.XWingMLKEM768X25519.PrivateKey) {
            cryptoKitPrivateKey = pk
        }
    }

    public struct KeyPair: Sendable {
        public let publicKey: PublicKey
        public let privateKey: PrivateKey
    }

    public static func generateKeyPair() throws -> KeyPair {
        do {
            let sk = try CryptoKitXWingAdapter.generatePrivateKey()
            let privateKey = PrivateKey(sk)

            return KeyPair(publicKey: privateKey.publicKey, privateKey: privateKey)
        } catch {
            throw ContainerKitError.keyGenerationFailed
        }
    }
}

public extension XWing {
    struct Ciphertext: Hashable, Sendable {
        public static let byteCount = 1120

        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == Self.byteCount else {
                throw ContainerKitError.invalidCiphertextRepresentation
            }

            self.rawRepresentation = rawRepresentation
        }
    }
}

// MARK: - CryptoKit bridges

internal extension XWing.PublicKey {
    func cryptoKitKey() throws -> CryptoKit.XWingMLKEM768X25519.PublicKey {
        do {
            return try CryptoKitXWingAdapter.makePublicKey(fromRaw: rawRepresentation)
        } catch {
            throw ContainerKitError.invalidKeyRepresentation
        }
    }
}

internal extension XWing.PrivateKey {
    var cryptoKitKey: CryptoKit.XWingMLKEM768X25519.PrivateKey {
        cryptoKitPrivateKey
    }
}
