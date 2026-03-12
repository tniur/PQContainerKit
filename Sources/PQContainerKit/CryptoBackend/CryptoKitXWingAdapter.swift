//
//  CryptoKitXWingAdapter.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 11.03.2026.
//

import CryptoKit
import Foundation

internal enum CryptoKitXWingAdapter {
    // MARK: - Keys

    static func generatePrivateKey() throws -> CryptoKit.XWingMLKEM768X25519.PrivateKey {
        try CryptoKit.XWingMLKEM768X25519.PrivateKey()
    }

    static func makePublicKey(fromRaw raw: Data) throws -> CryptoKit.XWingMLKEM768X25519.PublicKey {
        try CryptoKit.XWingMLKEM768X25519.PublicKey(rawRepresentation: raw)
    }

    static func publicKeyRaw(from privateKey: CryptoKit.XWingMLKEM768X25519.PrivateKey) -> Data {
        privateKey.publicKey.rawRepresentation
    }

    // MARK: - KEM

    static func encapsulate(
        to publicKey: CryptoKit.XWingMLKEM768X25519.PublicKey
    ) throws -> (SymmetricKey, Data) {
        let result = try publicKey.encapsulate()

        return (result.sharedSecret, result.encapsulated)
    }

    static func decapsulate(
        using privateKey: CryptoKit.XWingMLKEM768X25519.PrivateKey,
        encapsulated ciphertextRaw: Data
    ) throws -> SymmetricKey {
        try privateKey.decapsulate(ciphertextRaw)
    }
}
