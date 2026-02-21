//
//  DEKWrap.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation

/// Internal DEK wrapping/unwrapping using KEM-derived shared secret.
///
/// wrappedDEK format (v1, fixed for MVP):
/// - `wrappedDEK = ciphertext || tag`
///
/// Key and nonce are derived via HKDF-SHA256 from the ML-KEM shared secret:
/// - wrapKey:   HKDF(ss, salt=containerID||recipientKeyId, info="DEK_WRAP_KEY",   L=32)
/// - wrapNonce: HKDF(ss, salt=containerID||recipientKeyId, info="DEK_WRAP_NONCE", L=12)
///
/// AAD binds the wrap to the container and recipient:
/// - aad = containerID || recipientKeyId
internal enum DEKWrap {
    private static let dekByteCount = 32

    private static let infoWrapKey = Data("DEK_WRAP_KEY".utf8)
    private static let infoWrapNonce = Data("DEK_WRAP_NONCE".utf8)

    static func wrapDEK(
        dek: SymmetricKey,
        containerID: Data,
        recipientKeyId: Data,
        sharedSecret: SymmetricKey
    ) throws -> Data {
        let context = makeContext(containerID: containerID, recipientKeyId: recipientKeyId)

        let wrapKey = try HKDFSHA256.deriveKey(
            sharedSecret: sharedSecret,
            salt: context,
            info: infoWrapKey,
            length: dekByteCount
        )

        let wrapNonce = try HKDFSHA256.deriveBytes(
            sharedSecret: sharedSecret,
            salt: context,
            info: infoWrapNonce,
            length: AESGCM.nonceByteCount
        )

        var dekBytes = dek.withUnsafeBytes { Data($0) }

        defer { dekBytes.resetBytes(in: 0 ..< dekBytes.count) }

        let (ciphertext, tag) = try AESGCM.seal(
            dekBytes,
            key: wrapKey,
            nonce: wrapNonce,
            authenticating: context
        )

        var wrapped = Data()
        wrapped.append(ciphertext)
        wrapped.append(tag)

        return wrapped
    }

    static func unwrapDEK(
        wrappedDEK: Data,
        containerID: Data,
        recipientKeyId: Data,
        sharedSecret: SymmetricKey
    ) throws -> SymmetricKey {
        let context = makeContext(containerID: containerID, recipientKeyId: recipientKeyId)

        guard wrappedDEK.count > AESGCM.tagByteCount else {
            throw ContainerKitError.invalidWrappedDEKRepresentation
        }

        let tagStart = wrappedDEK.count - AESGCM.tagByteCount
        let ciphertext = Data(wrappedDEK[..<tagStart])
        let tag = Data(wrappedDEK[tagStart...])

        let wrapKey = try HKDFSHA256.deriveKey(
            sharedSecret: sharedSecret,
            salt: context,
            info: infoWrapKey,
            length: dekByteCount
        )

        let wrapNonce = try HKDFSHA256.deriveBytes(
            sharedSecret: sharedSecret,
            salt: context,
            info: infoWrapNonce,
            length: AESGCM.nonceByteCount
        )

        var dekBytes = try AESGCM.open(
            ciphertext: ciphertext,
            tag: tag,
            key: wrapKey,
            nonce: wrapNonce,
            authenticating: context
        )

        defer { dekBytes.resetBytes(in: 0 ..< dekBytes.count) }

        guard dekBytes.count == dekByteCount else {
            throw ContainerKitError.invalidWrappedDEKRepresentation
        }

        return SymmetricKey(data: dekBytes)
    }

    private static func makeContext(containerID: Data, recipientKeyId: Data) -> Data {
        var context = Data()
        context.append(containerID)
        context.append(recipientKeyId)

        return context
    }
}
