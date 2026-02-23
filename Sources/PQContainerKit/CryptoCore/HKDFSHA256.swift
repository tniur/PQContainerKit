//
//  HKDFSHA256.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation

internal enum HKDFSHA256 {
    static func deriveKey(sharedSecret: SymmetricKey, salt: Data, info: Data, length: Int) throws -> SymmetricKey {
        guard (1 ... 1024).contains(length) else {
            throw ContainerKitError.invalidKDFOutputLength
        }

        return CryptoKit.HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: salt,
            info: info,
            outputByteCount: length
        )
    }

    static func deriveBytes(sharedSecret: SymmetricKey, salt: Data, info: Data, length: Int) throws -> Data {
        let key = try deriveKey(
            sharedSecret: sharedSecret,
            salt: salt,
            info: info,
            length: length
        )

        return key.withUnsafeBytes { Data($0) }
    }
}
