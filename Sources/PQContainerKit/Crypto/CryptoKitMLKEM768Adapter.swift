//
//  CryptoKitMLKEM768Adapter.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import CryptoKit
import Foundation

enum CryptoKitMLKEM768Adapter {
    static func generatePrivateKey() throws -> MLKEM768.PrivateKey {
        try MLKEM768.PrivateKey()
    }

    static func publicKeyRaw(from privateKey: MLKEM768.PrivateKey) -> Data {
        privateKey.publicKey.rawRepresentation
    }

    static func makePublicKey(fromRaw raw: Data) throws -> MLKEM768.PublicKey {
        try MLKEM768.PublicKey(rawRepresentation: raw)
    }
}
