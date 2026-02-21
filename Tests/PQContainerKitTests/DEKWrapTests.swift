//
//  DEKWrapTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation
@testable import PQContainerKit
import Testing

@Suite("DEK wrap/unwrap")
struct DEKWrapTests {
    private func bytes(of key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    @Test("DEKWrap round-trip unwraps to the same DEK")
    func dekWrapRoundTrip() throws {
        let dek = SymmetricKey(size: .bits256)
        let sharedSecret = SymmetricKey(data: Data(repeating: 0x42, count: 32))

        let containerID = Data((0 ..< 16).map { UInt8($0) })
        let recipientKeyId = Data(repeating: 0xAA, count: 32)

        let wrapped = try DEKWrap.wrapDEK(
            dek: dek,
            containerID: containerID,
            recipientKeyId: recipientKeyId,
            sharedSecret: sharedSecret
        )

        let unwrapped = try DEKWrap.unwrapDEK(
            wrappedDEK: wrapped,
            containerID: containerID,
            recipientKeyId: recipientKeyId,
            sharedSecret: sharedSecret
        )

        #expect(bytes(of: unwrapped) == bytes(of: dek))
    }

    @Test("Wrong shared secret rejects unwrap (aeadFailed)")
    func dekWrapWrongSharedSecret() throws {
        let dek = SymmetricKey(size: .bits256)
        let sharedSecretA = SymmetricKey(data: Data(repeating: 0x11, count: 32))
        let sharedSecretB = SymmetricKey(data: Data(repeating: 0x22, count: 32))

        let containerID = Data(repeating: 0x01, count: 16)
        let recipientKeyId = Data(repeating: 0x02, count: 32)

        let wrapped = try DEKWrap.wrapDEK(
            dek: dek,
            containerID: containerID,
            recipientKeyId: recipientKeyId,
            sharedSecret: sharedSecretA
        )

        #expect(throws: PQContainerKit.ContainerKitError.aeadFailed) {
            _ = try DEKWrap.unwrapDEK(
                wrappedDEK: wrapped,
                containerID: containerID,
                recipientKeyId: recipientKeyId,
                sharedSecret: sharedSecretB
            )
        }
    }

    @Test("Tampering wrappedDEK rejects unwrap (aeadFailed)")
    func dekWrapTampering() throws {
        let dek = SymmetricKey(size: .bits256)
        let sharedSecret = SymmetricKey(data: Data(repeating: 0x33, count: 32))

        let containerID = Data(repeating: 0x10, count: 16)
        let recipientKeyId = Data(repeating: 0x20, count: 32)

        let wrapped = try DEKWrap.wrapDEK(
            dek: dek,
            containerID: containerID,
            recipientKeyId: recipientKeyId,
            sharedSecret: sharedSecret
        )

        var tampered = [UInt8](wrapped)
        #expect(!tampered.isEmpty)
        tampered[0] ^= 0x01

        #expect(throws: PQContainerKit.ContainerKitError.aeadFailed) {
            _ = try DEKWrap.unwrapDEK(
                wrappedDEK: Data(tampered),
                containerID: containerID,
                recipientKeyId: recipientKeyId,
                sharedSecret: sharedSecret
            )
        }
    }
}
