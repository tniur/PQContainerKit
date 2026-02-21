//
//  HKDFSHA256.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation

/// Internal HKDF-SHA256 helper for key derivation in CryptoCore.
///
/// Uses HKDF for key separation via `info` and binding to context via `salt`.
enum HKDFSHA256 {
    /// Derives a symmetric key using HKDF-SHA256.
    ///
    /// - Parameters:
    ///   - sharedSecret: Input key material (IKM), typically ML-KEM shared secret.
    ///   - salt: Context-binding salt (e.g., containerID || recipientKeyId).
    ///   - info: Purpose string / domain separation (e.g., "DEK_WRAP_KEY").
    ///   - length: Output key length in bytes.
    /// - Returns: Derived `SymmetricKey` of requested length.
    static func deriveKey(
        sharedSecret: SymmetricKey,
        salt: Data,
        info: Data,
        length: Int
    ) throws -> SymmetricKey {
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
}
