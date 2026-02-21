//
//  AESGCM.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation

/// Internal AES-256-GCM helper for sealing/opening payloads in CryptoCore.
///
/// Designed to work with container v1 layout where nonce/ciphertext/tag are stored separately.
enum AESGCM {
    static let nonceByteCount = 12
    static let tagByteCount = 16

    static func seal(
        _ plaintext: Data,
        key: SymmetricKey,
        nonce: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        try seal(plaintext, key: key, nonce: nonce, authenticating: Data())
    }

    static func seal(
        _ plaintext: Data,
        key: SymmetricKey,
        nonce: Data,
        authenticating aad: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        guard nonce.count == nonceByteCount else {
            throw ContainerKitError.invalidNonceLength
        }

        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealed = try AES.GCM.seal(plaintext, using: key, nonce: gcmNonce, authenticating: aad)
            return (ciphertext: sealed.ciphertext, tag: sealed.tag)
        } catch {
            throw ContainerKitError.aeadFailed
        }
    }

    static func open(
        ciphertext: Data,
        tag: Data,
        key: SymmetricKey,
        nonce: Data
    ) throws -> Data {
        try open(ciphertext: ciphertext, tag: tag, key: key, nonce: nonce, authenticating: Data())
    }

    static func open(
        ciphertext: Data,
        tag: Data,
        key: SymmetricKey,
        nonce: Data,
        authenticating aad: Data
    ) throws -> Data {
        guard nonce.count == nonceByteCount else {
            throw ContainerKitError.invalidNonceLength
        }
        guard tag.count == tagByteCount else {
            throw ContainerKitError.invalidTagLength
        }

        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw ContainerKitError.aeadFailed
        }
    }
}
