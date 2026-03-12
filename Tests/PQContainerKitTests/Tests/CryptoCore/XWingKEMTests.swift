//
//  XWingKEMTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 12.03.2026.
//

import CryptoKit
import Foundation
@testable import PQContainerKit
import Testing

@Suite("CryptoCore: X-Wing (KEM)")
struct XWingKEMTests {
    @Test("Encapsulate/decapsulate yields identical shared secret")
    func kemCorrectnessUT04() throws {
        let pair = try XWing.generateKeyPair()

        let kem = try XWing.encapsulate(to: pair.publicKey)
        let ss2 = try XWing.decapsulate(
            privateKey: pair.privateKey,
            ciphertext: kem.ciphertext
        )

        #expect(TestByteUtils.data(of: kem.sharedSecret) == TestByteUtils.data(of: ss2))
    }

    @Test("Decapsulate with different private key yields different shared secret")
    func kemIsolationUT05() throws {
        let keyPair1 = try XWing.generateKeyPair()
        let keyPair2 = try XWing.generateKeyPair()

        let kem = try XWing.encapsulate(to: keyPair1.publicKey)
        let ssWrong = try XWing.decapsulate(
            privateKey: keyPair2.privateKey,
            ciphertext: kem.ciphertext
        )

        #expect(TestByteUtils.data(of: kem.sharedSecret) != TestByteUtils.data(of: ssWrong))
    }

    @Test("Ciphertext initializer rejects invalid length")
    func ciphertextValidation() {
        #expect(throws: PQContainerKit.ContainerKitError.invalidCiphertextRepresentation) {
            _ = try XWing.Ciphertext(rawRepresentation: Data(repeating: 0, count: 1))
        }
    }
}
