//
//  AESGCMTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation
@testable import PQContainerKit
import Testing

@Suite("AES-GCM")
struct AESGCMTests {
    @Test("UT-01: AES-GCM round-trip")
    func aesGcmRoundTripUT01() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data((0 ..< AESGCM.nonceByteCount).map { UInt8($0) })
        let plaintext = Data("hello pq".utf8)

        let sealed = try AESGCM.seal(plaintext, key: key, nonce: nonce)
        let opened = try AESGCM.open(
            ciphertext: sealed.ciphertext,
            tag: sealed.tag,
            key: key,
            nonce: nonce
        )

        #expect(opened == plaintext)
    }

    @Test("UT-02: Tampering ciphertext rejects (aeadFailed)")
    func aesGcmTamperCiphertextUT02() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data((0 ..< AESGCM.nonceByteCount).map { UInt8($0) })
        let plaintext = Data("tamper me".utf8)

        let sealed = try AESGCM.seal(plaintext, key: key, nonce: nonce)

        var tamperedCiphertextBytes = [UInt8](sealed.ciphertext)
        #expect(!tamperedCiphertextBytes.isEmpty)
        tamperedCiphertextBytes[0] ^= 0x01

        let tamperedCiphertext = Data(tamperedCiphertextBytes)

        #expect(throws: PQContainerKit.ContainerKitError.aeadFailed) {
            _ = try AESGCM.open(
                ciphertext: tamperedCiphertext,
                tag: sealed.tag,
                key: key,
                nonce: nonce
            )
        }
    }

    @Test("UT-02: Tampering tag rejects (aeadFailed)")
    func aesGcmTamperTagUT02() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data((0 ..< AESGCM.nonceByteCount).map { UInt8($0) })
        let plaintext = Data("tag tamper".utf8)

        let sealed = try AESGCM.seal(plaintext, key: key, nonce: nonce)

        var tamperedTagBytes = [UInt8](sealed.tag)
        #expect(tamperedTagBytes.count == AESGCM.tagByteCount)
        tamperedTagBytes[0] ^= 0x01

        let tamperedTag = Data(tamperedTagBytes)

        #expect(throws: PQContainerKit.ContainerKitError.aeadFailed) {
            _ = try AESGCM.open(
                ciphertext: sealed.ciphertext,
                tag: tamperedTag,
                key: key,
                nonce: nonce
            )
        }
    }

    @Test("UT-03: Wrong key rejects (aeadFailed)")
    func aesGcmWrongKeyUT03() throws {
        let keyA = SymmetricKey(size: .bits256)
        let keyB = SymmetricKey(size: .bits256)
        let nonce = Data((0 ..< AESGCM.nonceByteCount).map { UInt8($0) })
        let plaintext = Data("wrong key".utf8)

        let sealed = try AESGCM.seal(plaintext, key: keyA, nonce: nonce)

        #expect(throws: PQContainerKit.ContainerKitError.aeadFailed) {
            _ = try AESGCM.open(
                ciphertext: sealed.ciphertext,
                tag: sealed.tag,
                key: keyB,
                nonce: nonce
            )
        }
    }

    @Test("Nonce validation rejects invalid nonce length")
    func nonceValidation() throws {
        let key = SymmetricKey(size: .bits256)
        let badNonce = Data(repeating: 0x00, count: 1)
        let plaintext = Data("nonce".utf8)

        #expect(throws: PQContainerKit.ContainerKitError.invalidNonceLength) {
            _ = try AESGCM.seal(plaintext, key: key, nonce: badNonce)
        }
    }

    @Test("Tag validation rejects invalid tag length")
    func tagValidation() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data((0 ..< AESGCM.nonceByteCount).map { UInt8($0) })
        let plaintext = Data("tag".utf8)

        let sealed = try AESGCM.seal(plaintext, key: key, nonce: nonce)
        let badTag = Data(repeating: 0x00, count: 1)

        #expect(throws: PQContainerKit.ContainerKitError.invalidTagLength) {
            _ = try AESGCM.open(
                ciphertext: sealed.ciphertext,
                tag: badTag,
                key: key,
                nonce: nonce
            )
        }
    }
}
