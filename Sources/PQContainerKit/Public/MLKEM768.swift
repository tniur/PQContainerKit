//
//  MLKEM768.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import CryptoKit
import Foundation

public extension PQContainerKit {
    @available(iOS 26.0, macOS 26.0, *)
    enum MLKEM768 {
        public struct PublicKey: Hashable, Sendable {
            public let rawRepresentation: Data

            public init(rawRepresentation: Data) throws {
                _ = try CryptoKitMLKEM768Adapter.makePublicKey(fromRaw: rawRepresentation)
                self.rawRepresentation = rawRepresentation
            }

            public init(base64: String) throws {
                guard let data = Data(base64Encoded: base64) else {
                    throw PQContainerKit.Error.invalidBase64
                }
                try self.init(rawRepresentation: data)
            }

            public var base64: String {
                rawRepresentation.base64EncodedString()
            }

            public var fingerprint: PQContainerKit.Fingerprint {
                PQContainerKit.Fingerprint.fromPublicKeyRaw(rawRepresentation)
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
                throw PQContainerKit.Error.keyGenerationFailed
            }
        }
    }
}
