//
//  MLKEM768.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import CryptoKit
import Foundation

public enum MLKEM768 {
    public struct PublicKey: Hashable, Sendable {
        public let rawRepresentation: Data
        public init(rawRepresentation: Data) throws {
            do {
                _ = try CryptoKitMLKEM768Adapter.makePublicKey(fromRaw: rawRepresentation)
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

        public var base64: String {
            rawRepresentation.base64EncodedString()
        }

        public var fingerprint: Fingerprint {
            Fingerprint.fromPublicKeyRaw(rawRepresentation)
        }

        init(uncheckedRawRepresentation: Data) {
            rawRepresentation = uncheckedRawRepresentation
        }
    }

    public struct PrivateKey: Sendable {
        fileprivate let cryptoKitPrivateKey: CryptoKit.MLKEM768.PrivateKey

        fileprivate init(_ pk: CryptoKit.MLKEM768.PrivateKey) {
            cryptoKitPrivateKey = pk
        }

        public var publicKey: PublicKey {
            let raw = CryptoKitMLKEM768Adapter.publicKeyRaw(from: cryptoKitPrivateKey)
            return PublicKey(uncheckedRawRepresentation: raw)
        }
    }

    public struct KeyPair: Sendable {
        public let publicKey: PublicKey

        public let privateKey: PrivateKey
    }

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
    struct Ciphertext: Hashable, Sendable {
        public static let byteCount = 1088

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

internal extension MLKEM768.PublicKey {
    func cryptoKitKey() throws -> CryptoKit.MLKEM768.PublicKey {
        do {
            return try CryptoKitMLKEM768Adapter.makePublicKey(fromRaw: rawRepresentation)
        } catch {
            throw ContainerKitError.invalidKeyRepresentation
        }
    }
}

internal extension MLKEM768.PrivateKey {
    var cryptoKitKey: CryptoKit.MLKEM768.PrivateKey {
        cryptoKitPrivateKey
    }
}
