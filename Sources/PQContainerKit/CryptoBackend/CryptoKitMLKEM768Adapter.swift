//
//  CryptoKitMLKEM768Adapter.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import CryptoKit
import Foundation

internal enum CryptoKitMLKEM768Adapter {
    // MARK: - Keys

    static func generatePrivateKey() throws -> CryptoKit.MLKEM768.PrivateKey {
        try CryptoKit.MLKEM768.PrivateKey()
    }

    static func makePublicKey(fromRaw raw: Data) throws -> CryptoKit.MLKEM768.PublicKey {
        try CryptoKit.MLKEM768.PublicKey(rawRepresentation: raw)
    }

    static func publicKeyRaw(from privateKey: CryptoKit.MLKEM768.PrivateKey) -> Data {
        privateKey.publicKey.rawRepresentation
    }

    // MARK: - KEM

    static func encapsulate(to publicKey: CryptoKit.MLKEM768.PublicKey) throws -> (SymmetricKey, Data) {
        let result = try publicKey.encapsulate()

        return (result.sharedSecret, result.encapsulated)
    }

    static func decapsulate(
        using privateKey: CryptoKit.MLKEM768.PrivateKey,
        encapsulated ciphertextRaw: Data
    ) throws -> SymmetricKey {
        try privateKey.decapsulate(ciphertextRaw)
    }
}
